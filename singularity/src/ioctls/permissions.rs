use shared::ioctl::ChangeProcessPplLevel;
use wdk::{nt_success, println};
use wdk_sys::{call_unsafe_wdf_function_binding, NTSTATUS, STATUS_SUCCESS, WDFREQUEST__};

// Import our DKOM logic from the internals module
use crate::internals::dkom::change_process_ppl;

/// Handles the change PPL IOCTL request. It dynamically alters the
/// target process protection level via DKOM.
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
pub unsafe fn handle_change_ppl(request: *mut WDFREQUEST__) -> (NTSTATUS, u64) {
    let mut input_buffer: *mut core::ffi::c_void = core::ptr::null_mut();
    let mut input_size: usize = 0;

    // SAFETY: We pass valid pointers to receive the buffer. WDF validates that the
    // buffer size matches at least the size of `ChangePermissionsRequest`.
    let status = unsafe {
        call_unsafe_wdf_function_binding!(
            WdfRequestRetrieveInputBuffer,
            request,
            core::mem::size_of::<ChangeProcessPplLevel>(),
            &raw mut input_buffer,
            &raw mut input_size
        )
    };

    if !nt_success(status) {
        println!(
            "[Singularity::permissions] Error: Failed to retrieve input buffer {status:#010X}"
        );
        return (status, 0);
    }

    // SAFETY: WDF guarantees the buffer is valid and appropriately sized per the call above.
    // `kmdf_client` goes out of scope here. The RAII `Drop` implementation
    // will safely call CloseHandle(), detaching from the driver.
    let req = unsafe { &*(input_buffer as *const ChangeProcessPplLevel) };

    println!(
        "[Singularity::permissions] Requesting permissions change for PID: {} to Level: {:#02X}",
        req.process_id, req.level
    );

    let dkom_status = match change_process_ppl(req.process_id, req.level) {
        Ok(_) => STATUS_SUCCESS,
        Err(e) => e,
    };

    // The output buffer length is 0 since this IOCTL does not return data, only a status code.
    (dkom_status, 0)
}
