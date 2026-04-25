#![no_std]

#[cfg(not(test))]
extern crate wdk_panic;

#[cfg(not(test))]
use wdk_alloc::WdkAllocator;

#[cfg(not(test))]
#[global_allocator]
static GLOBAL_ALLOCATOR: WdkAllocator = WdkAllocator;

use shared::GUID_SINGULARITY;
use wdk::{nt_success, paged_code, println};
use wdk_sys::{
    NTSTATUS, PCUNICODE_STRING, PDRIVER_OBJECT, PWDFDEVICE_INIT, ULONG, WDF_DRIVER_CONFIG,
    WDF_NO_HANDLE, WDF_NO_OBJECT_ATTRIBUTES, WDFDEVICE, WDFDRIVER,
    call_unsafe_wdf_function_binding,
};

/// `DriverEntry` initializes the driver and is the first routine called by the
/// system after the driver is loaded. `DriverEntry` specifies the other entry
/// points in the function driver, such as `EvtDevice` and `DriverUnload`.
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
#[unsafe(export_name = "DriverEntry")] // WDF expects a symbol with the name DriverEntry
pub unsafe extern "system" fn driver_entry(
    driver: PDRIVER_OBJECT, // NOTE: In Kernel Mode crates, you can use driver: &mut DRIVER_OBJECT instead of driver: PDRIVER_OBJECT.
    registry_path: PCUNICODE_STRING,
) -> NTSTATUS {
    let mut driver_config = WDF_DRIVER_CONFIG {
        Size: core::mem::size_of::<WDF_DRIVER_CONFIG>() as ULONG,
        EvtDriverDeviceAdd: Some(singularity_device_add),
        ..WDF_DRIVER_CONFIG::default()
    };
    let driver_handle_output = WDF_NO_HANDLE.cast::<WDFDRIVER>();

    let nt_status = unsafe {
        call_unsafe_wdf_function_binding!(
            WdfDriverCreate,
            driver as PDRIVER_OBJECT,
            registry_path,
            WDF_NO_OBJECT_ATTRIBUTES,
            &raw mut driver_config,
            driver_handle_output,
        )
    };

    if !nt_success(nt_status) {
        println!("Error: WdfDriverCreate failed {nt_status:#010X}");
    }

    nt_status
}

/// `EvtDeviceAdd` is called by the framework in response to `AddDevice`
/// call from the `PnP` manager. We create and initialize a device object to
/// represent a new instance of the device.
///
/// # Arguments:
///
/// * `_driver` - Handle to a framework driver object created in `DriverEntry`
/// * `device_init` - Pointer to a framework-allocated `WDFDEVICE_INIT`
///   structure.
///
/// # Return value:
///
///   * `NTSTATUS`
#[unsafe(link_section = "PAGE")]
extern "C" fn singularity_device_add(
    _driver: WDFDRIVER,
    mut device_init: PWDFDEVICE_INIT,
) -> NTSTATUS {
    paged_code!();
    println!("Enter  SingularityDeviceAdd");

    let mut device = WDF_NO_HANDLE as WDFDEVICE;
    // WdfDeviceCreate takes a pointer to a PWDFDEVICE_INIT (*mut PWDFDEVICE_INIT).
    // It consumes the pointer and sets the caller's variable to NULL upon success.
    let mut nt_status = unsafe {
        call_unsafe_wdf_function_binding!(
            WdfDeviceCreate,
            core::ptr::addr_of_mut!(device_init),
            WDF_NO_OBJECT_ATTRIBUTES,
            &raw mut device,
        )
    };

    if !nt_success(nt_status) {
        println!("Error: WdfDeviceCreate failed {nt_status:#010X}");
    } else {
        // Create a device interface so that application can find and talk to us.
        nt_status = unsafe {
            call_unsafe_wdf_function_binding!(
                WdfDeviceCreateDeviceInterface,
                device,
                &GUID_SINGULARITY as *const _ as *const wdk_sys::GUID,
                core::ptr::null_mut(),
            )
        };
    }

    // TODO: Create a queue with wdfIoQueueCrate

    nt_status
}
