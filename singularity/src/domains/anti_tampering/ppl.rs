//! Process Protection Level (PPL) modification routines.

use wdk::nt_success;
use wdk_sys::{
    PEPROCESS, RTL_OSVERSIONINFOW,
    ntddk::{PsLookupProcessByProcessId, RtlGetVersion},
};

use super::error::AntiTamperingError;
use crate::foundation::raii::EprocessGuard;

/// Resolves the EPROCESS Protection byte offset dynamically by checking the Windows kernel build number.
///
/// Hardcoding a single offset corrupts adjacent kernel memory and triggers BSODs on differing Windows builds.
fn get_eprocess_protection_offset() -> Result<usize, AntiTamperingError> {
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
        // Windows 11 24H2+ (Build 26100+)
        b if b >= 26100 => Ok(0x5FA),
        // Windows 11 21H2 - 23H2 (Build 22000..26100)
        22000..26100 => Ok(0x87A),
        // Windows 10 2004 - 22H2 (Build 19041 - 19045)
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
/// # Arguments
///
/// * `pid` - The Process ID of the user-mode target to modify.
/// * `level` - The raw protection byte value to apply (e.g., 0x31 for PPL-Antimalware).
///
/// # Errors
///
/// Returns [`AntiTamperingError`] if:
/// * The PID is invalid (e.g., PID 0).
/// * The protection level byte specifies an invalid `PS_PROTECTION.Type`.
/// * The Windows build is unsupported.
/// * The process lookup fails or returns a null pointer.
pub fn change_process_ppl(pid: u32, level: u8) -> Result<(), AntiTamperingError> {
    // Validate target PID (PID 0 is System Idle process)
    if pid == 0 {
        crate::driver_error!("[anti_tampering::ppl] Rejected modification for PID 0 (System Idle)");
        return Err(AntiTamperingError::InvalidProcessId(pid));
    }

    // Validate PS_PROTECTION format:
    // Bits 0..2 represent Type (0 = None, 1 = ProtectedLight, 2 = Protected).
    // Types > 2 are invalid/undefined in the NT kernel.
    let protection_type = level & 0x07;
    if protection_type > 2 {
        crate::driver_error!(
            "[anti_tampering::ppl] Rejected invalid protection type ({protection_type}) in byte {level:#02X}"
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

    let process_guard = EprocessGuard::new(process);

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
