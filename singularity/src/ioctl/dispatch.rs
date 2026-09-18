//! Central IOCTL queue event callback and request completion router.

use shared::ioctl::IOCTL_CHANGE_PPL_LEVEL;
use wdk_sys::{call_unsafe_wdf_function_binding, NTSTATUS, STATUS_SUCCESS, WDFQUEUE__, WDFREQUEST__};

use super::handlers;
use super::IoctlError;
use crate::foundation::error::DriverError;

/// Handles incoming Device Control (IOCTL) requests from WDF queues.
///
/// Dispatches the request to the appropriate handler, maps any resulting [`DriverError`]
/// to an `NTSTATUS` code, and completes the `WDFREQUEST`.
pub unsafe extern "C" fn singularity_device_control(
    _queue: *mut WDFQUEUE__,
    request: *mut WDFREQUEST__,
    _output_buffer_length: usize,
    _input_buffer_length: usize,
    io_control_code: u32,
) {
    // Hot-path receipt logging is compiled out in release builds for zero-overhead performance
    crate::driver_debug!("[ioctl::dispatch] Received IOCTL: {io_control_code:#010X}");

    let result: Result<usize, DriverError> = match io_control_code {
        IOCTL_CHANGE_PPL_LEVEL => unsafe { handlers::handle_change_ppl(request) },
        unknown => {
            crate::driver_warn!("[ioctl::dispatch] Unrecognized IOCTL: {unknown:#010X}");
            Err(DriverError::Ioctl(IoctlError::InvalidDeviceRequest(unknown)))
        }
    };

    let (status, bytes_returned): (NTSTATUS, usize) = match result {
        Ok(bytes) => (STATUS_SUCCESS, bytes),
        Err(err) => {
            let status = err.to_ntstatus();
            crate::driver_error!("[ioctl::dispatch] Request failed: {err} ({status:#010X})");
            (status, 0)
        }
    };

    // SAFETY: We are completing the WDFREQUEST provided by the framework.
    unsafe {
        if bytes_returned > 0 {
            call_unsafe_wdf_function_binding!(
                WdfRequestCompleteWithInformation,
                request,
                status,
                bytes_returned as u64
            );
        } else {
            call_unsafe_wdf_function_binding!(WdfRequestComplete, request, status);
        }
    }
}
