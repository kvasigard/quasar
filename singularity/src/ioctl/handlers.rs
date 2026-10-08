//! Domain command handlers executed in response to incoming IOCTL requests.

use shared::ioctl::{ChangeProcessPplLevel, PerCpuMapResponse, RegisterEventRequest};
use wdk_sys::{call_unsafe_wdf_function_binding, WDFREQUEST__};

use super::IoctlError;
use crate::comm::ring_buffer;
use crate::domains::anti_tampering;
use crate::foundation::error::DriverError;

/// Handles the `IOCTL_CHANGE_PPL_LEVEL` request by routing to the anti-tampering domain.
///
/// Decodes the target PID and protection level byte from the framework input buffer,
/// modifies the process protection in the NT kernel, and completes the request with 0 output bytes.
///
/// # Safety
/// The caller must ensure `request` is a valid, uncompleted `WDFREQUEST` pointer provided by the framework.
///
/// # Arguments
///
/// * `request` - Framework request object holding the `ChangeProcessPplLevel` payload.
///
/// # Return values
///
/// * `Ok(0)` - Protection level applied successfully with zero return bytes.
/// * `Err(DriverError::Ioctl)` - Input buffer retrieval error.
/// * `Err(DriverError::AntiTampering)` - PPL elevation failure.
pub(crate) unsafe fn handle_change_ppl(request: *mut WDFREQUEST__) -> Result<usize, DriverError> {
    let mut input_buffer: *mut core::ffi::c_void = core::ptr::null_mut();
    let mut input_size: usize = 0;

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
        crate::driver_error!("[ioctl::handlers] Failed to retrieve input buffer ({status:#010X})");
        return Err(IoctlError::BufferRetrievalFailed(status).into());
    }

    let req = unsafe { &*(input_buffer as *const ChangeProcessPplLevel) };

    crate::driver_debug!(
        "[ioctl::handlers] Requesting permissions change for PID: {} to Level: {:#02X}",
        req.process_id,
        req.level
    );

    anti_tampering::change_process_ppl(req.process_id, req.level)?;
    Ok(0)
}

/// Handles the `IOCTL_MAP_PER_CPU_BUFFER` request by projecting per-CPU pools into the calling process.
///
/// Builds MDLs for the data and status ring buffer regions, projects them into the user process,
/// and populates the `PerCpuMapResponse` output buffer with the mapped virtual addresses.
///
/// # Safety
/// The caller must ensure `request` is a valid, uncompleted `WDFREQUEST` pointer provided by the framework.
///
/// # Arguments
///
/// * `request` - Framework request object holding the output buffer.
///
/// # Return values
///
/// * `Ok(usize)` - Size in bytes of the populated `PerCpuMapResponse` payload.
/// * `Err(DriverError::Ioctl)` - Output buffer retrieval error.
/// * `Err(DriverError::RingBuffer)` - MDL allocation or user-mode projection error.
pub(crate) unsafe fn handle_map_per_cpu_buffer(request: *mut WDFREQUEST__) -> Result<usize, DriverError> {
    crate::driver_debug!("[ioctl::handlers] Processing IOCTL_MAP_PER_CPU_BUFFER request");

    let mut output_buffer: *mut core::ffi::c_void = core::ptr::null_mut();
    let mut output_size: usize = 0;

    let status = unsafe {
        call_unsafe_wdf_function_binding!(
            WdfRequestRetrieveOutputBuffer,
            request,
            core::mem::size_of::<PerCpuMapResponse>(),
            &raw mut output_buffer,
            &raw mut output_size
        )
    };

    if !wdk::nt_success(status) {
        crate::driver_error!(
            "[ioctl::handlers] Failed to retrieve output buffer for map request ({status:#010X})"
        );
        return Err(IoctlError::BufferRetrievalFailed(status).into());
    }

    let response = ring_buffer::create_user_mapping()?;

    crate::driver_debug!(
        "[ioctl::handlers] Mapping successful: Data @ {:#018X}, Status @ {:#018X}, Cores: {}",
        response.data_address,
        response.status_address,
        response.cpu_count
    );

    unsafe {
        output_buffer
            .cast::<PerCpuMapResponse>()
            .write(response);
    }

    Ok(core::mem::size_of::<PerCpuMapResponse>())
}

/// Handles the `IOCTL_REGISTER_EVENT` request by registering a Win32 event for kernel notification.
///
/// Decodes the user-mode event handle from the request, references the underlying kernel event object,
/// and binds it to the active ring buffer session.
///
/// # Safety
/// The caller must ensure `request` is a valid, uncompleted `WDFREQUEST` pointer provided by the framework.
///
/// # Arguments
///
/// * `request` - Framework request object containing the `RegisterEventRequest` input buffer.
///
/// # Return values
///
/// * `Ok(0)` - Win32 event registered successfully with zero output bytes.
/// * `Err(DriverError::Ioctl)` - Input buffer retrieval or handle dereferencing failure.
pub(crate) unsafe fn handle_register_event(request: *mut WDFREQUEST__) -> Result<usize, DriverError> {
    let mut input_buffer: *mut core::ffi::c_void = core::ptr::null_mut();
    let mut input_size: usize = 0;

    let status = unsafe {
        call_unsafe_wdf_function_binding!(
            WdfRequestRetrieveInputBuffer,
            request,
            core::mem::size_of::<RegisterEventRequest>(),
            &raw mut input_buffer,
            &raw mut input_size
        )
    };

    if !wdk::nt_success(status) {
        crate::driver_error!(
            "[ioctl::handlers] Failed to retrieve input buffer for register event ({status:#010X})"
        );
        return Err(IoctlError::BufferRetrievalFailed(status).into());
    }

    let req = unsafe { *input_buffer.cast::<RegisterEventRequest>() };

    crate::driver_debug!(
        "[ioctl::handlers] Processing IOCTL_REGISTER_EVENT with handle {:#018X}",
        req.event_handle
    );

    let res = unsafe {
        ring_buffer::register_notification_event(req.event_handle as wdk_sys::HANDLE)
    };

    if let Err(status) = res {
        crate::driver_error!(
            "[ioctl::handlers] Failed to reference notification event handle ({status:#010X})"
        );
        return Err(IoctlError::BufferRetrievalFailed(status).into());
    }

    Ok(0)
}
