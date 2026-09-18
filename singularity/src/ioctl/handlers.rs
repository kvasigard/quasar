//! Domain command handlers executed in response to incoming IOCTL requests.

use shared::ioctl::ChangeProcessPplLevel;
use wdk_sys::{call_unsafe_wdf_function_binding, WDFREQUEST__};

use super::IoctlError;
use crate::domains::anti_tampering;
use crate::foundation::error::DriverError;

/// Handles the `IOCTL_CHANGE_PPL_LEVEL` request by routing to the anti-tampering domain.
///
/// # Returns
/// A result containing the number of bytes returned on success, or a [`DriverError`] on failure.
///
/// # Safety
/// The caller must ensure `request` is a valid, uncompleted `WDFREQUEST` pointer provided by the framework.
pub unsafe fn handle_change_ppl(request: *mut WDFREQUEST__) -> Result<usize, DriverError> {
    let mut input_buffer: *mut core::ffi::c_void = core::ptr::null_mut();
    let mut input_size: usize = 0;

    // Retrieve input buffer with size validation
    let status = unsafe {
        call_unsafe_wdf_function_binding!(
            WdfRequestRetrieveInputBuffer,
            request,
            core::mem::size_of::<ChangeProcessPplLevel>(),
            &raw mut input_buffer,
            &raw mut input_size
        )
    };

    if !wdk::nt_success(status) {
        crate::driver_error!(
            "[ioctl::handlers] Failed to retrieve input buffer ({status:#010X})"
        );
        return Err(IoctlError::BufferRetrievalFailed(status).into());
    }

    // SAFETY: WDF guarantees the input buffer is valid, non-null, and sized to at least
    // `size_of::<ChangeProcessPplLevel>()` per the retrieval call above. Because the IOCTL
    // uses METHOD_BUFFERED, user-mode cannot mutate the buffer concurrently.
    let req = unsafe { &*(input_buffer as *const ChangeProcessPplLevel) };

    // Debug-only logging prevents leaking sensitive target PID telemetry into release debug buffers
    crate::driver_debug!(
        "[ioctl::handlers] Requesting permissions change for PID: {} to Level: {:#02X}",
        req.process_id,
        req.level
    );

    // Route to the anti-tampering domain
    anti_tampering::change_process_ppl(req.process_id, req.level)?;

    // Output length is 0 bytes for this IOCTL
    Ok(0)
}
