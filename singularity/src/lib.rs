#![no_std]

#[cfg(not(test))]
extern crate wdk_panic;

#[cfg(not(test))]
use wdk_alloc::WdkAllocator;

#[cfg(not(test))]
#[global_allocator]
static GLOBAL_ALLOCATOR: WdkAllocator = WdkAllocator;

use shared::{IOCTL_SINGULARITY_PING, PingRequest, PingResponse};
use wdk::{nt_success, println};
use wdk_sys::{
    _WDF_IO_QUEUE_CONFIG, NTSTATUS, PCUNICODE_STRING, PDRIVER_OBJECT,
    STATUS_INSUFFICIENT_RESOURCES, STATUS_INVALID_DEVICE_REQUEST, STATUS_SUCCESS, ULONG,
    WDF_DRIVER_CONFIG, WDF_NO_OBJECT_ATTRIBUTES, WDFDEVICE, WDFDRIVER, WDFQUEUE, WDFQUEUE__,
    WDFREQUEST__, call_unsafe_wdf_function_binding, ntddk::RtlInitUnicodeString,
};

/// `DriverEntry` initializes the driver and is the first routine called by the
/// system after the driver is loaded. `DriverEntry` specifies the other entry
/// points in the function driver. Since this is a Non-PnP driver, we also create
/// the Control Device directly here.
///
/// # Arguments
///
/// * `driver` - represents the instance of the function driver that is loaded
///   into memory. `DriverEntry` must initialize members of `DriverObject`
///   before it returns to the caller. `DriverObject` is allocated by the system
///   before the driver is loaded, and it is released by the system after the
///   system unloads the function driver from memory.
/// * `registry_path` - represents the driver specific path in the Registry. The
///   function driver can use the path to store driver related data between
///   reboots. The path does not store hardware instance specific data.
///
/// # Return value:
///
/// * `STATUS_SUCCESS` - if successful,
/// * `STATUS_UNSUCCESSFUL` - otherwise.
#[unsafe(link_section = "INIT")]
#[unsafe(export_name = "DriverEntry")] // WDF expects a symbol with the exact name DriverEntry
pub unsafe extern "system" fn driver_entry(
    driver: PDRIVER_OBJECT,
    registry_path: PCUNICODE_STRING,
) -> NTSTATUS {
    println!("[Singularity::driver_entry] Entering driver_entry");

    let mut driver_config = WDF_DRIVER_CONFIG {
        Size: core::mem::size_of::<WDF_DRIVER_CONFIG>() as ULONG,
        // No AddDevice callback needed for Non-PnP drivers
        EvtDriverDeviceAdd: None,
        // Require Unload callback for Non-PnP drivers so we can unload it
        EvtDriverUnload: Some(singularity_driver_unload),
        // Tell the framework this is a Non-PnP software driver
        DriverInitFlags: wdk_sys::_WDF_DRIVER_INIT_FLAGS::WdfDriverInitNonPnpDriver as u32,
        ..WDF_DRIVER_CONFIG::default()
    };

    let mut driver_handle: WDFDRIVER = core::ptr::null_mut();

    // Create the WDF Driver Object
    let mut nt_status = unsafe {
        call_unsafe_wdf_function_binding!(
            WdfDriverCreate,
            driver,
            registry_path,
            WDF_NO_OBJECT_ATTRIBUTES,
            &raw mut driver_config,
            &raw mut driver_handle,
        )
    };

    if !nt_success(nt_status) {
        println!("[Singularity::driver_entry] Error: WdfDriverCreate failed {nt_status:#010X}");
        return nt_status;
    }

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
        println!("[Singularity::driver_entry] Error: WdfControlDeviceInitAllocate failed");
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

    nt_status = unsafe {
        call_unsafe_wdf_function_binding!(WdfDeviceInitAssignName, device_init, &device_name)
    };

    if !nt_success(nt_status) {
        println!(
            "[Singularity::driver_entry] Error: WdfDeviceInitAssignName failed {nt_status:#010X}"
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
        println!("[Singularity::driver_entry] Error: WdfDeviceCreate failed {nt_status:#010X}");
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
            "[Singularity::driver_entry] Error: WdfDeviceCreateSymbolicLink failed {nt_status:#010X}"
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
        println!("[Singularity::driver_entry] Error: WdfIoQueueCreate failed {nt_status:#010X}");
        return nt_status;
    }

    // Signal the framework that the control device is fully initialized
    // This is mandatory for Non-PnP drivers.
    unsafe {
        call_unsafe_wdf_function_binding!(WdfControlFinishInitializing, device);
    }

    println!("[Singularity::driver_entry] Control Device initialized successfully");
    STATUS_SUCCESS
}

/// Handles incoming Device Control (IOCTL) requests.
///
/// # Arguments
///
/// * `_queue` - Handle to the framework queue object that is associated with the I/O request.
/// * `request` - Handle to a framework request object.
/// * `_output_buffer_length` - Length, in bytes, of the request's output buffer.
/// * `_input_buffer_length` - Length, in bytes, of the request's input buffer.
/// * `io_control_code` - The driver-defined or system-defined I/O control code.
unsafe extern "C" fn singularity_device_control(
    _queue: *mut WDFQUEUE__,
    request: *mut WDFREQUEST__,
    _output_buffer_length: usize,
    _input_buffer_length: usize,
    io_control_code: u32,
) {
    println!("[Singularity::singularity_device_control] Received IOCTL: {io_control_code:#010X}");

    let mut bytes_returned: u64 = 0;

    let status = match io_control_code {
        IOCTL_SINGULARITY_PING => {
            // SAFETY: The `request` pointer is provided by WDF and is valid for this callback.
            let (status, bytes) = unsafe { handle_ping(request) };
            bytes_returned = bytes;
            status
        }
        _ => {
            println!("[Singularity::singularity_device_control] Warning: Unrecognized IOCTL");
            STATUS_INVALID_DEVICE_REQUEST
        }
    };

    // If bytes were returned, WDF needs to know the exact size to safely copy
    // the data from the kernel buffer back to the user buffer.
    //
    // SAFETY: We are completing the WDFREQUEST provided by the framework with a valid NTSTATUS.
    // The framework guarantees the request handle is valid until WdfRequestComplete is called.
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

/// Handles the Ping IOCTL logic.
/// Retrieves input and output buffers from the framework and validates magic values.
///
/// # Arguments
///
/// * `request` - Handle to a framework request object containing user buffers.
///
/// # Return value:
///
/// * A tuple containing the `NTSTATUS` and the number of bytes written to the output buffer.
unsafe fn handle_ping(request: *mut WDFREQUEST__) -> (NTSTATUS, u64) {
    let mut input_buffer: *mut core::ffi::c_void = core::ptr::null_mut();
    let mut input_size: usize = 0;

    // SAFETY: `request` is a valid handle provided by the framework. We pass valid raw
    // pointers to receive the buffer address and size. WDF safely validates the requested size.
    let mut status = unsafe {
        call_unsafe_wdf_function_binding!(
            WdfRequestRetrieveInputBuffer,
            request,
            core::mem::size_of::<PingRequest>(),
            &raw mut input_buffer,
            &raw mut input_size
        )
    };

    if !nt_success(status) {
        println!("[Singularity::handle_ping] Failed to retrieve input buffer {status:#010X}");
        return (status, 0);
    }

    let mut output_buffer: *mut core::ffi::c_void = core::ptr::null_mut();
    let mut output_size: usize = 0;

    // SAFETY: `request` is a valid handle. We pass valid raw pointers to receive the
    // buffer address and size. WDF safely validates the requested size.
    status = unsafe {
        call_unsafe_wdf_function_binding!(
            WdfRequestRetrieveOutputBuffer,
            request,
            core::mem::size_of::<PingResponse>(),
            &raw mut output_buffer,
            &raw mut output_size
        )
    };

    if !nt_success(status) {
        println!("[Singularity::handle_ping] Failed to retrieve output buffer {status:#010X}");
        return (status, 0);
    }

    // Cast WDF-provided raw buffers into our Shared memory structures.
    //
    // SAFETY: WDF guarantees that the buffers retrieved via WdfRequestRetrieveInput/OutputBuffer
    // are at least the requested size (verified by the API calls above) and are valid for
    // the duration of the request. We are safe to dereference them into Rust references.
    let (ping_req, ping_resp) = unsafe {
        (
            &*(input_buffer as *const PingRequest),
            &mut *(output_buffer as *mut PingResponse),
        )
    };

    println!(
        "[Singularity::handle_ping] Received Ping from PID: {} | Magic: {:#X}",
        ping_req.process_id, ping_req.magic_value
    );

    // Business Logic: Verify the user-mode app sent the correct magic value
    if ping_req.magic_value == 0xDEADBEEF {
        ping_resp.success = true;
        ping_resp.message_code = 0x1337;
    } else {
        ping_resp.success = false;
        ping_resp.message_code = 0x0;
    }

    (STATUS_SUCCESS, core::mem::size_of::<PingResponse>() as u64)
}

unsafe extern "C" fn singularity_driver_unload(_driver: WDFDRIVER) {
    println!("[Singularity] Unloading driver...");
}
