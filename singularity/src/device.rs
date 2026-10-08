use wdk::nt_success;
use wdk_sys::{
    _WDF_FILEOBJECT_CLASS, _WDF_FILEOBJECT_CONFIG, _WDF_IO_QUEUE_CONFIG, _WDF_TRI_STATE, NTSTATUS,
    STATUS_INSUFFICIENT_RESOURCES, ULONG, WDF_NO_OBJECT_ATTRIBUTES, WDFDEVICE, WDFFILEOBJECT,
    WDFDRIVER, WDFQUEUE, call_unsafe_wdf_function_binding,
};

use crate::foundation::init_unicode_string;
use crate::ioctl::singularity_device_control;

/// Domain-specific errors for control device and queue creation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceError {
    /// Failed to allocate the control device initialization structure.
    ControlDeviceInitAllocateFailed,

    /// Assigning the device name failed.
    DeviceInitAssignNameFailed(NTSTATUS),

    /// Framework device object creation failed.
    DeviceCreateFailed(NTSTATUS),

    /// Creating the symbolic link failed.
    SymbolicLinkCreateFailed(NTSTATUS),

    /// Default I/O queue creation failed.
    QueueCreateFailed(NTSTATUS),
}

impl DeviceError {
    /// Converts the device error into its corresponding Windows NTSTATUS code.
    pub const fn to_ntstatus(&self) -> NTSTATUS {
        match self {
            Self::ControlDeviceInitAllocateFailed => STATUS_INSUFFICIENT_RESOURCES,
            Self::DeviceInitAssignNameFailed(status)
            | Self::DeviceCreateFailed(status)
            | Self::SymbolicLinkCreateFailed(status)
            | Self::QueueCreateFailed(status) => *status,
        }
    }
}

impl core::fmt::Display for DeviceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ControlDeviceInitAllocateFailed => {
                write!(f, "Failed to allocate control device initialization structure")
            }
            Self::DeviceInitAssignNameFailed(status) => {
                write!(f, "WdfDeviceInitAssignName failed ({status:#010X})")
            }
            Self::DeviceCreateFailed(status) => {
                write!(f, "WdfDeviceCreate failed ({status:#010X})")
            }
            Self::SymbolicLinkCreateFailed(status) => {
                write!(f, "WdfDeviceCreateSymbolicLink failed ({status:#010X})")
            }
            Self::QueueCreateFailed(status) => {
                write!(f, "WdfIoQueueCreate failed ({status:#010X})")
            }
        }
    }
}

impl core::error::Error for DeviceError {}

/// Callback invoked by KMDF when a user-mode process closes its handle or terminates.
///
/// # Critical Safety Rationale (Process CR3 Context)
/// `EvtFileCleanup` executes while the processor is still running in the virtual memory context
/// of the terminating user process (i.e. the CR3 page directory register still references
/// the user process's page tables). This guarantees that [`MmUnmapLockedPages`] can safely walk
/// and dismantle user-mode Page Table Entries (PTEs) without triggering bugchecks.
///
/// # Arguments
///
/// * `_file_object` - Framework file object representing the open device instance being closed.
unsafe extern "C" fn device_file_cleanup(_file_object: WDFFILEOBJECT) {
    crate::driver_info!(
        "[device::file_cleanup] User client handle closed or process terminated. Unmapping per-CPU ring buffers."
    );
    crate::comm::ring_buffer::teardown_user_mapping();
}

/// Creates and initializes the Non-PnP Control Device and sequential dispatch queue.
///
/// # Safety
/// The caller must ensure `driver_handle` is a valid, initialized WDFDRIVER object.
///
/// # Arguments
///
/// * `driver_handle` - The framework driver object created in DriverEntry.
///
/// # Return values
///
/// * `Ok(())` - Control device, symbolic link, and default I/O queue initialized.
/// * `Err(DeviceError::ControlDeviceInitAllocateFailed)` - WDF failed to allocate init block.
/// * `Err(DeviceError::DeviceInitAssignNameFailed)` - Device object name assignment failed.
/// * `Err(DeviceError::DeviceCreateFailed)` - WDF device object creation failed.
/// * `Err(DeviceError::SymbolicLinkCreateFailed)` - DosDevices symlink creation failed.
/// * `Err(DeviceError::QueueCreateFailed)` - Framework I/O queue creation failed.
pub(crate) unsafe fn create_control_device(driver_handle: WDFDRIVER) -> Result<(), DeviceError> {
    // Construct the SDDL string to secure the control device (System and Administrators only).
    let sddl_buffer = windows_sys::w!("D:P(A;;GA;;;SY)(A;;GA;;;BA)");
    let sddl_string = unsafe { init_unicode_string(sddl_buffer) };

    // Allocate a Control Device Initialization structure
    let mut device_init = unsafe {
        call_unsafe_wdf_function_binding!(WdfControlDeviceInitAllocate, driver_handle, &sddl_string)
    };

    if device_init.is_null() {
        crate::driver_error!("[device::create_control_device] WdfControlDeviceInitAllocate failed");
        return Err(DeviceError::ControlDeviceInitAllocateFailed);
    }

    // Assign a Device Name before creating the device.
    // Non-PnP devices require an internal kernel name.
    let device_name_buffer = windows_sys::w!("\\Device\\SingularityDevice");
    let device_name = unsafe { init_unicode_string(device_name_buffer) };

    let mut nt_status = unsafe {
        call_unsafe_wdf_function_binding!(WdfDeviceInitAssignName, device_init, &device_name)
    };

    if !nt_success(nt_status) {
        crate::driver_error!(
            "[device::create_control_device] WdfDeviceInitAssignName failed {nt_status:#010X}"
        );
        // We must manually free device_init if an error occurs BEFORE calling WdfDeviceCreate
        unsafe {
            call_unsafe_wdf_function_binding!(WdfDeviceInitFree, device_init);
        }
        return Err(DeviceError::DeviceInitAssignNameFailed(nt_status));
    }

    // Configure file tracking so EvtFileCleanup executes when user handle closes
    let mut file_config = _WDF_FILEOBJECT_CONFIG {
        Size: core::mem::size_of::<_WDF_FILEOBJECT_CONFIG>() as ULONG,
        EvtFileCleanup: Some(device_file_cleanup),
        EvtFileClose: None,
        EvtDeviceFileCreate: None,
        AutoForwardCleanupClose: _WDF_TRI_STATE::WdfFalse,
        FileObjectClass: _WDF_FILEOBJECT_CLASS::WdfFileObjectWdfCannotUseFsContexts,
    };

    unsafe {
        call_unsafe_wdf_function_binding!(
            WdfDeviceInitSetFileObjectConfig,
            device_init,
            &raw mut file_config,
            WDF_NO_OBJECT_ATTRIBUTES,
        );
    }

    let mut device: WDFDEVICE = core::ptr::null_mut();

    // Create the Device
    // SAFETY: WdfDeviceCreate consumes the device_init pointer. If it fails, WDF frees it.
    nt_status = unsafe {
        call_unsafe_wdf_function_binding!(
            WdfDeviceCreate,
            &raw mut device_init,
            WDF_NO_OBJECT_ATTRIBUTES,
            &raw mut device,
        )
    };

    if !nt_success(nt_status) {
        crate::driver_error!(
            "[device::create_control_device] WdfDeviceCreate failed {nt_status:#010X}"
        );
        return Err(DeviceError::DeviceCreateFailed(nt_status));
    }

    // Create a Symbolic Link instead of a Device Interface.
    let symlink_buffer = windows_sys::w!("\\DosDevices\\SingularityDevice");
    let symlink_string = unsafe { init_unicode_string(symlink_buffer) };

    nt_status = unsafe {
        call_unsafe_wdf_function_binding!(WdfDeviceCreateSymbolicLink, device, &symlink_string)
    };

    if !nt_success(nt_status) {
        crate::driver_error!(
            "[device::create_control_device] WdfDeviceCreateSymbolicLink failed {nt_status:#010X}"
        );
        return Err(DeviceError::SymbolicLinkCreateFailed(nt_status));
    }

    // Configure the default I/O queue to sequential dispatching
    let mut queue_config = _WDF_IO_QUEUE_CONFIG {
        Size: core::mem::size_of::<_WDF_IO_QUEUE_CONFIG>() as ULONG,
        DispatchType: wdk_sys::_WDF_IO_QUEUE_DISPATCH_TYPE::WdfIoQueueDispatchSequential,
        EvtIoDeviceControl: Some(singularity_device_control),
        DefaultQueue: 1,
        .._WDF_IO_QUEUE_CONFIG::default()
    };

    let mut queue: WDFQUEUE = core::ptr::null_mut();
    nt_status = unsafe {
        call_unsafe_wdf_function_binding!(
            WdfIoQueueCreate,
            device,
            &raw mut queue_config,
            WDF_NO_OBJECT_ATTRIBUTES,
            &raw mut queue
        )
    };

    if !nt_success(nt_status) {
        crate::driver_error!(
            "[device::create_control_device] WdfIoQueueCreate failed {nt_status:#010X}"
        );
        return Err(DeviceError::QueueCreateFailed(nt_status));
    }

    // Signal the framework that the control device is fully initialized
    // This is mandatory for Non-PnP drivers.
    unsafe {
        call_unsafe_wdf_function_binding!(WdfControlFinishInitializing, device);
    }

    crate::driver_info!("[device::create_control_device] Control Device initialized successfully");
    Ok(())
}
