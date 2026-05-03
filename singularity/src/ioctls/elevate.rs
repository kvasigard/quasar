use shared::ProcessProtectionRequest;
use wdk::{nt_success, println};
use wdk_sys::{NTSTATUS, STATUS_SUCCESS, WDFREQUEST__, call_unsafe_wdf_function_binding};

// Import our DKOM logic from the internals module
use crate::internals::dkom::elevate_process_to_ppl;

/// Handles the process elevation IOCTL request. It elevates the requested process to PPL
/// Antimalware level.
///
/// # Arguments
///
/// * `request` - A raw handle to the WDF framework request object containing the user's buffer.
///
/// # Returns
///
/// A tuple containing the resulting `NTSTATUS` of the operation and the number of bytes
/// to return to the user-mode caller.
///
/// # Safety
///
/// The caller must ensure that the `request` pointer is a valid, framework-supplied handle.
/// The function utilizes safe WDF abstractions to validate the input buffer size before
/// dereferencing the memory into a Rust reference.
pub unsafe fn handle_elevate(request: *mut WDFREQUEST__) -> (NTSTATUS, u64) {
    let mut input_buffer: *mut core::ffi::c_void = core::ptr::null_mut();
    let mut input_size: usize = 0;

    // SAFETY: We pass valid pointers to receive the buffer. WDF validates that the
    // buffer size matches at least the size of `ProcessProtectionRequest`.
    let status = unsafe {
        call_unsafe_wdf_function_binding!(
            WdfRequestRetrieveInputBuffer,
            request,
            core::mem::size_of::<ProcessProtectionRequest>(),
            &raw mut input_buffer,
            &raw mut input_size
        )
    };

    if !nt_success(status) {
        println!("[Singularity::elevate] Error: Failed to retrieve input buffer {status:#010X}");
        return (status, 0);
    }

    // SAFETY: WDF guarantees the buffer is valid and appropriately sized per the call above.
    let req = unsafe { &*(input_buffer as *const ProcessProtectionRequest) };

    println!(
        "[Singularity::elevate] Requesting PPL change for PID: {}",
        req.target_pid
    );

    let dkom_status = match elevate_process_to_ppl(req.target_pid) {
        Ok(_) => STATUS_SUCCESS,
        Err(e) => e,
    };

    // The output buffer length is 0 since this IOCTL does not return data, only a status code.
    (dkom_status, 0)
}
