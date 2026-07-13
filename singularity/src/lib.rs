#![no_std]

#[cfg(not(test))]
extern crate wdk_panic;

#[cfg(not(test))]
use wdk_alloc::WdkAllocator;

#[cfg(not(test))]
#[global_allocator]
static GLOBAL_ALLOCATOR: WdkAllocator = WdkAllocator;

// ========================================================================
// MODULE DECLARATIONS
// ========================================================================
pub mod device;
pub mod internals;
pub mod ioctls;
pub mod raii;

use wdk::{nt_success, println};
use wdk_sys::{
    NTSTATUS, PCUNICODE_STRING, PDRIVER_OBJECT, ULONG, WDF_DRIVER_CONFIG, WDF_NO_OBJECT_ATTRIBUTES,
    WDFDRIVER, call_unsafe_wdf_function_binding,
};

/// `DriverEntry` initializes the driver and is the first routine called by the
/// system after the driver is loaded. `DriverEntry` specifies the other entry
/// points in the function driver. Since this is a Non-PnP driver, we initiate
/// the creation of the Control Device from here.
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
    let nt_status = unsafe {
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

    // Delegate Control Device and Queue creation to our device module
    unsafe { device::create_control_device(driver_handle) }
}

unsafe extern "C" fn singularity_driver_unload(_driver: WDFDRIVER) {
    println!("[Singularity] Unloading driver...");
}
