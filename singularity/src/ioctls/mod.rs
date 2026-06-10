pub mod permissions;

use shared::ioctl::IOCTL_CHANGE_PPL_LEVEL;
use wdk::println;
use wdk_sys::{
    call_unsafe_wdf_function_binding, STATUS_INVALID_DEVICE_REQUEST, WDFQUEUE__, WDFREQUEST__,
};

/// Handles incoming Device Control (IOCTL) requests.
///
/// # Arguments
/// * `_queue` - Handle to the framework queue object that is associated with the I/O request.
/// * `request` - Handle to a framework request object.
/// * `_output_buffer_length` - Length, in bytes, of the request's output buffer.
/// * `_input_buffer_length` - Length, in bytes, of the request's input buffer.
/// * `io_control_code` - The driver-defined or system-defined I/O control code.
pub unsafe extern "C" fn singularity_device_control(
    _queue: *mut WDFQUEUE__,
    request: *mut WDFREQUEST__,
    _output_buffer_length: usize,
    _input_buffer_length: usize,
    io_control_code: u32,
) {
    println!("[Singularity::ioctls] Received IOCTL: {io_control_code:#010X}");

    let mut bytes_returned: u64 = 0;

    let status = match io_control_code {
        IOCTL_CHANGE_PPL_LEVEL => {
            // SAFETY: The `request` pointer is provided by WDF and is valid for this callback.
            unsafe {
                let (status, bytes) = permissions::handle_change_ppl(request);
                bytes_returned = bytes;
                status
            }
        }
        _ => {
            println!("[Singularity::ioctls] Warning: Unrecognized IOCTL");
            STATUS_INVALID_DEVICE_REQUEST
        }
    };

    // If bytes were returned, WDF needs to know the exact size to safely copy
    // the data from the kernel buffer back to the user buffer.
    //
    // SAFETY: We are completing the WDFREQUEST provided by the framework with a valid NTSTATUS.
    unsafe {
        if bytes_returned > 0 {
            call_unsafe_wdf_function_binding!(
                WdfRequestCompleteWithInformation,
                request,
                status,
                bytes_returned
            );
        } else {
            call_unsafe_wdf_function_binding!(WdfRequestComplete, request, status);
        }
    }
}
