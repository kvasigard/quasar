#![no_std]

#[cfg(not(test))]
extern crate wdk_panic;

#[cfg(not(test))]
use wdk_alloc::WdkAllocator;

#[cfg(not(test))]
#[global_allocator]
static GLOBAL_ALLOCATOR: WdkAllocator = WdkAllocator;

pub mod comm;
pub mod device;
pub mod domains;
pub mod foundation;
pub mod ioctl;
pub mod wrappers;

// Re-export println for $crate::println! macro expansion in foundation::log
pub use wdk::println;

use foundation::error::DriverError;
use foundation::state::DRIVER_STATE;
use wdk::nt_success;
use wdk_sys::{
    NTSTATUS, PCUNICODE_STRING, PDRIVER_OBJECT, STATUS_SUCCESS, ULONG, WDF_DRIVER_CONFIG,
    WDF_NO_OBJECT_ATTRIBUTES, WDFDRIVER, call_unsafe_wdf_function_binding,
};

/// Internal initialization sequence returning typed [`DriverError`].
///
/// # Safety
/// Caller must ensure `driver` and `registry_path` are valid pointers provided by the OS loader.
unsafe fn initialize_driver(
    driver: PDRIVER_OBJECT,
    registry_path: PCUNICODE_STRING,
) -> Result<(), DriverError> {
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
        return Err(DriverError::WdfDriverCreate(nt_status));
    }

    // Create the Non-PnP Control Device and Sequential Queue
    unsafe { device::create_control_device(driver_handle)? };
    DRIVER_STATE.mark_device_created();

    // Create the Shared Memory ring
    comm::ring_buffer::initialize()?;
    DRIVER_STATE.mark_ring_created();

    // Register Object Manager callbacks
    domains::callbacks::initialize()?;
    DRIVER_STATE.mark_callbacks_registered();

    // Mark driver as fully initialized and ready
    DRIVER_STATE.mark_initialized();
    Ok(())
}

/// `DriverEntry` initializes the driver and is the first routine called by the
/// system after the driver is loaded. Since this is a Non-PnP driver, we initiate
/// the creation of the Control Device from here.
///
/// # Arguments
///
/// * `driver` - represents the instance of the function driver loaded into memory.
/// * `registry_path` - represents the driver specific path in the Registry.
///
/// # Return value:
///
/// * `STATUS_SUCCESS` - if successful,
/// * Corresponding Windows NTSTATUS error code otherwise.
#[unsafe(link_section = "INIT")]
#[unsafe(export_name = "DriverEntry")] // WDF expects a symbol with the exact name DriverEntry
pub unsafe extern "system" fn driver_entry(
    driver: PDRIVER_OBJECT,
    registry_path: PCUNICODE_STRING,
) -> NTSTATUS {
    driver_info!("[driver_entry] Entering DriverEntry");

    match unsafe { initialize_driver(driver, registry_path) } {
        Ok(()) => {
            driver_info!("[driver_entry] Singularity initialized successfully");
            STATUS_SUCCESS
        }
        Err(err) => {
            let status = err.to_ntstatus();
            driver_error!("[driver_entry] Initialization failed: {err} ({status:#010X})");
            // Perform rollback on already initialized subsystems
            DRIVER_STATE.cleanup_all();
            status
        }
    }
}

/// Invoked by WDF when the driver is being unloaded from memory.
unsafe extern "C" fn singularity_driver_unload(_driver: WDFDRIVER) {
    driver_info!("[unload] Unloading Singularity driver...");
    DRIVER_STATE.cleanup_all();
}
