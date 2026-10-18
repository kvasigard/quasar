//! Process Protection Level (PPL) modification routines.

use wdk::nt_success;
use wdk_sys::{
    PASSIVE_LEVEL, PEPROCESS, RTL_OSVERSIONINFOW, STATUS_INVALID_DEVICE_STATE,
    ntddk::{PsLookupProcessByProcessId, RtlGetVersion},
};

use super::error::AntiTamperingError;
use crate::foundation::irql::ensure_max_irql;
use crate::foundation::raii::EprocessGuard;

/// Resolves the EPROCESS Protection byte offset dynamically by checking the Windows kernel build number.
///
/// Hardcoding a single offset corrupts adjacent kernel memory and triggers BSODs on differing Windows builds.
/// Only explicitly verified Windows build numbers are permitted.
///
/// # Return values
///
/// * `Ok(usize)` - Verified byte offset of `PS_PROTECTION` inside `EPROCESS`.
/// * `Err(AntiTamperingError::VersionDetectionFailed)` - `RtlGetVersion` call failed or IRQL > `PASSIVE_LEVEL`.
/// * `Err(AntiTamperingError::UnsupportedWindowsBuild)` - Running on an untested or incompatible Windows kernel build.
fn get_eprocess_protection_offset() -> Result<usize, AntiTamperingError> {
    if ensure_max_irql(PASSIVE_LEVEL as u8).is_err() {
        return Err(AntiTamperingError::VersionDetectionFailed(
            STATUS_INVALID_DEVICE_STATE,
        ));
    }

    let mut version_info: RTL_OSVERSIONINFOW = unsafe { core::mem::zeroed() };
    version_info.dwOSVersionInfoSize = core::mem::size_of::<RTL_OSVERSIONINFOW>() as u32;

    let status = unsafe { RtlGetVersion(&mut version_info) };
    if !nt_success(status) {
        crate::driver_error!("[anti_tampering::ppl] RtlGetVersion failed ({status:#010X})");
        return Err(AntiTamperingError::VersionDetectionFailed(status));
    }

    let build = version_info.dwBuildNumber;
    crate::driver_debug!(
        "[anti_tampering::ppl] Detected Windows Build Number: {}",
        build
    );

    match build {
        // Windows 11 24H2 / 25H2 (Verified builds 26100, 26200)
        26100 | 26200 => Ok(0x5FA),
        // Windows 11 21H2, 22H2, 23H2 (Verified builds 22000, 22621, 22631)
        22000 | 22621 | 22631 => Ok(0x87A),
        // Windows 10 2004 - 22H2 (Verified builds 19041 - 19045)
        19041..=19045 => Ok(0x87A),
        _ => {
            crate::driver_error!(
                "[anti_tampering::ppl] Unsupported Windows build: {}",
                build
            );
            Err(AntiTamperingError::UnsupportedWindowsBuild(build))
        }
    }
}

/// Changes the protection level byte of the specified process.
///
/// Looks up the target `PEPROCESS` via `PsLookupProcessByProcessId`, computes the version-specific
/// `PS_PROTECTION` offset, and applies the new protection byte atomically using volatile writes.
///
/// # Arguments
///
/// * `pid` - The Process ID of the user-mode target to modify.
/// * `level` - The raw protection byte value to apply (e.g., 0x31 for PPL-Antimalware).
///
/// # Return values
///
/// * `Ok(())` - Process protection byte updated successfully.
/// * `Err(AntiTamperingError::InvalidProcessId)` - Target PID is invalid (e.g. PID 0 or PID 4).
/// * `Err(AntiTamperingError::InvalidProtectionLevel)` - Protection byte specifies invalid type or signer, or attempts to strip protection (`0`).
/// * `Err(AntiTamperingError::UnsupportedWindowsBuild)` - Kernel build unsupported.
/// * `Err(AntiTamperingError::ProcessLookupFailed)` - `PsLookupProcessByProcessId` returned NT error.
/// * `Err(AntiTamperingError::ProcessNotFound)` - Process lookup returned null.
pub(crate) fn change_process_ppl(pid: u32, level: u8) -> Result<(), AntiTamperingError> {
    if ensure_max_irql(PASSIVE_LEVEL as u8).is_err() {
        return Err(AntiTamperingError::ProcessLookupFailed(
            STATUS_INVALID_DEVICE_STATE,
        ));
    }

    // Validate target PID (PID 0 is System Idle process, PID 4 is System process)
    if pid == 0 || pid == 4 {
        crate::driver_error!(
            "[anti_tampering::ppl] Rejected modification for protected system PID {pid}"
        );
        return Err(AntiTamperingError::InvalidProcessId(pid));
    }

    // Reject stripping PPL protection (level == 0) and validate PS_PROTECTION bitfields:
    // Bits 0..2: Type (1 = ProtectedLight, 2 = Protected)
    // Bits 4..7: Signer (1..=8)
    let protection_type = level & 0x07;
    let signer = (level >> 4) & 0x0F;
    if level == 0 || !(1..=2).contains(&protection_type) || !(1..=8).contains(&signer) {
        crate::driver_error!(
            "[anti_tampering::ppl] Rejected invalid protection byte {level:#02X} (type: {protection_type}, signer: {signer})"
        );
        return Err(AntiTamperingError::InvalidProtectionLevel(level));
    }

    let offset = get_eprocess_protection_offset()?;
    let mut process: PEPROCESS = core::ptr::null_mut();

    // SAFETY: Casting the u32 PID to a HANDLE is the expected FFI pattern for NTOSKRNL.
    // We pass a valid mutable reference to receive the PEPROCESS pointer.
    let status = unsafe { PsLookupProcessByProcessId((pid as usize) as _, &mut process) };
    if !nt_success(status) {
        crate::driver_error!(
            "[anti_tampering::ppl] Failed to lookup PID {}: {:#010X}",
            pid, status
        );
        return Err(AntiTamperingError::ProcessLookupFailed(status));
    }

    if process.is_null() {
        crate::driver_error!(
            "[anti_tampering::ppl] PsLookupProcessByProcessId returned null pointer for PID {}",
            pid
        );
        return Err(AntiTamperingError::ProcessNotFound);
    }

    // SAFETY: `process` is a valid, newly-referenced PEPROCESS returned by PsLookupProcessByProcessId.
    let process_guard = unsafe { EprocessGuard::new(process) };

    // SAFETY: We hold a valid, reference-counted pointer to the EPROCESS structure
    // managed by EprocessGuard. Volatile reads and writes are mandatory here because
    // this memory is actively accessed by the kernel concurrently.
    let _old_value = unsafe {
        let process_base = process_guard.as_ptr() as *mut u8;
        let protection_addr = process_base.add(offset);

        let old = core::ptr::read_volatile(protection_addr);
        core::ptr::write_volatile(protection_addr, level);
        old
    };

    // Use driver_debug! to prevent leaking sensitive PID/kernel telemetry in release builds
    crate::driver_debug!(
        "[anti_tampering::ppl] Success. PID: {} | Offset: {:#X} | Old: {:#02X} -> New: {:#02X}",
        pid, offset, _old_value, level
    );

    Ok(())
}
