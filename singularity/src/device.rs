use wdk::{nt_success, println};
use wdk_sys::{
    _WDF_IO_QUEUE_CONFIG, NTSTATUS, STATUS_INSUFFICIENT_RESOURCES, STATUS_SUCCESS, ULONG,
    WDF_NO_OBJECT_ATTRIBUTES, WDFDEVICE, WDFDRIVER, WDFQUEUE, call_unsafe_wdf_function_binding,
    ntddk::RtlInitUnicodeString,
};

// Import the dispatcher function from our ioctls module
use crate::ioctls::singularity_device_control;

/// Creates and initializes the Non-PnP Control Device.
///
/// # Arguments
/// * `driver_handle` - The framework driver object created in DriverEntry.
pub unsafe fn create_control_device(driver_handle: WDFDRIVER) -> NTSTATUS {
    // Construct the SDDL string to secure the control device (System and Administrators only).
    let sddl_buffer = windows_sys::w!("D:P(A;;GA;;;SY)(A;;GA;;;BA)");

    // Initialize the UNICODE_STRING.
    let sddl_string = unsafe {
        let mut sddl_uninit = core::mem::MaybeUninit::<wdk_sys::UNICODE_STRING>::uninit();
        RtlInitUnicodeString(sddl_uninit.as_mut_ptr(), sddl_buffer);
        sddl_uninit.assume_init()
    };

    // Allocate a Control Device Initialization structure
    let mut device_init = unsafe {
        call_unsafe_wdf_function_binding!(WdfControlDeviceInitAllocate, driver_handle, &sddl_string)
    };

    if device_init.is_null() {
        println!("[Singularity::create_control_device] Error: WdfControlDeviceInitAllocate failed");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Assign a Device Name before creating the device.
    // Non-PnP devices require an internal kernel name.
    let device_name_buffer = windows_sys::w!("\\Device\\Singularity");
    let device_name = unsafe {
        let mut name_uninit = core::mem::MaybeUninit::<wdk_sys::UNICODE_STRING>::uninit();
        RtlInitUnicodeString(name_uninit.as_mut_ptr(), device_name_buffer);
        name_uninit.assume_init()
    };

    let mut nt_status = unsafe {
        call_unsafe_wdf_function_binding!(WdfDeviceInitAssignName, device_init, &device_name)
    };

    if !nt_success(nt_status) {
        println!(
            "[Singularity::create_control_device] Error: WdfDeviceInitAssignName failed {nt_status:#010X}"
        );
        // We must manually free device_init if an error occurs BEFORE calling WdfDeviceCreate
        unsafe {
            call_unsafe_wdf_function_binding!(WdfDeviceInitFree, device_init);
        }
        return nt_status;
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
        println!(
            "[Singularity::create_control_device] Error: WdfDeviceCreate failed {nt_status:#010X}"
        );
        return nt_status;
    }

    // Create a Symbolic Link instead of a Device Interface.
    let symlink_buffer = windows_sys::w!("\\DosDevices\\Singularity");
    let symlink_string = unsafe {
        let mut symlink_uninit = core::mem::MaybeUninit::<wdk_sys::UNICODE_STRING>::uninit();
        RtlInitUnicodeString(symlink_uninit.as_mut_ptr(), symlink_buffer);
        symlink_uninit.assume_init()
    };

    nt_status = unsafe {
        call_unsafe_wdf_function_binding!(WdfDeviceCreateSymbolicLink, device, &symlink_string)
    };

    if !nt_success(nt_status) {
        println!(
            "[Singularity::create_control_device] Error: WdfDeviceCreateSymbolicLink failed {nt_status:#010X}"
        );
        return nt_status;
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
        println!(
            "[Singularity::create_control_device] Error: WdfIoQueueCreate failed {nt_status:#010X}"
        );
        return nt_status;
    }

    // Signal the framework that the control device is fully initialized
    // This is mandatory for Non-PnP drivers.
    unsafe {
        call_unsafe_wdf_function_binding!(WdfControlFinishInitializing, device);
    }

    println!("[Singularity::create_control_device] Control Device initialized successfully");
    STATUS_SUCCESS
}
