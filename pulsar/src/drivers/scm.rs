//! Provides functionality for managing Windows kernel drivers.
//!
//! This module interacts with the Windows Service Control Manager (SCM) to
//! register, start, stop, and delete kernel drivers dynamically at runtime.

use crate::error::AppError;
use crate::win_last_error;
use std::ffi::c_void;
use std::ptr;
use windows_sys::Win32::Foundation::{
    ERROR_INSUFFICIENT_BUFFER, ERROR_SERVICE_ALREADY_RUNNING, ERROR_SERVICE_DOES_NOT_EXIST,
    GetLastError,
};
use windows_sys::Win32::System::Services::{
    CloseServiceHandle, ControlService, CreateServiceW, DeleteService, OpenSCManagerW,
    OpenServiceW, QueryServiceConfigW, QueryServiceStatus, QUERY_SERVICE_CONFIGW,
    SC_MANAGER_ALL_ACCESS, SERVICE_ALL_ACCESS, SERVICE_CONTROL_STOP, SERVICE_DEMAND_START,
    SERVICE_ERROR_NORMAL, SERVICE_KERNEL_DRIVER, SERVICE_QUERY_CONFIG, SERVICE_QUERY_STATUS,
    SERVICE_RUNNING, SERVICE_START, SERVICE_STATUS, SERVICE_STOP, StartServiceW,
};

/// A safe RAII wrapper around Windows Service Control handles.
///
/// Automatically closes the underlying handle when it falls out of scope,
/// preventing handle leaks.
struct ScmHandle(*mut c_void);

impl Drop for ScmHandle {
    fn drop(&mut self) {
        // Enforce that we do not attempt to close invalid/null handles
        if !self.0.is_null() {
            // SAFETY: The handle is guaranteed to be valid and owned by this struct.
            // It is safe to close, and doing so prevents resource leaks.
            unsafe {
                CloseServiceHandle(self.0);
            }
        }
    }
}

/// Registers and starts the kernel driver located at the specified path.
///
/// This function attempts to open the Service Control Manager, create a new
/// service entry for the driver (or open it if it already exists), and then
/// starts the service.
///
/// # Errors
///
/// Returns an `AppError` if:
/// - The Service Control Manager cannot be opened.
/// - The service creation or opening fails.
/// - The service fails to start (unless it is already running).
pub fn load_driver(driver_path: &str) -> Result<(), AppError> {
    log::debug!("Opening Service Control Manager...");

    // SAFETY: Passing null pointers for machine name and database name targets the
    // local machine and the ServicesActive database. SC_MANAGER_ALL_ACCESS is a valid
    // access right constant.
    let scm = unsafe { OpenSCManagerW(ptr::null(), ptr::null(), SC_MANAGER_ALL_ACCESS) };
    if scm.is_null() {
        return Err(win_last_error!());
    }
    let scm_handle = ScmHandle(scm);

    let service_name = windows_sys::w!("Singularity");

    // SAFETY: `scm_handle.0` is a valid handle to the SCM. `service_name` is a valid,
    // statically allocated null-terminated UTF-16 string.
    let service = unsafe {
        OpenServiceW(
            scm_handle.0,
            service_name,
            SERVICE_START | SERVICE_ALL_ACCESS,
        )
    };

    let service_handle = if service.is_null() {
        // SAFETY: GetLastError is always safe to call and simply returns the thread-local error code.
        let err = unsafe { GetLastError() };
        if err != ERROR_SERVICE_DOES_NOT_EXIST {
            return Err(win_last_error!());
        }

        log::info!("Registering Singularity driver...");

        // Encode to null-terminated UTF-16 wide string for Win32 API consumption
        let mut wide_path: Vec<u16> = driver_path.encode_utf16().collect();
        wide_path.push(0);

        // SAFETY:
        // - `scm_handle.0` is a valid SCM handle.
        // - `service_name` is a valid static null-terminated UTF-16 string.
        // - `wide_path.as_ptr()` points to a valid, null-terminated UTF-16 string that lives
        //   for the duration of this call.
        // - Passing null pointers for the optional configuration parameters is permitted by the Win32 API.
        let new_service = unsafe {
            CreateServiceW(
                scm_handle.0,
                service_name,
                service_name,
                SERVICE_ALL_ACCESS,
                SERVICE_KERNEL_DRIVER,
                SERVICE_DEMAND_START,
                SERVICE_ERROR_NORMAL,
                wide_path.as_ptr(),
                ptr::null(),
                ptr::null_mut(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
            )
        };

        if new_service.is_null() {
            return Err(win_last_error!());
        }
        ScmHandle(new_service)
    } else {
        ScmHandle(service)
    };

    log::debug!("Starting Singularity driver...");

    // SAFETY: `service_handle.0` is a valid handle to the service. Passing `0` for the argument count
    // and `ptr::null()` for the argument vector is explicitly permitted for services taking no arguments.
    let start_result = unsafe { StartServiceW(service_handle.0, 0, ptr::null()) };

    if start_result == 0 {
        // SAFETY: GetLastError is safe to call to inspect the thread-local error of the previous failure.
        let err = unsafe { GetLastError() };
        if err != ERROR_SERVICE_ALREADY_RUNNING {
            return Err(win_last_error!());
        }
    }

    Ok(())
}

/// Stops and unregisters the currently loaded kernel driver.
///
/// This function attempts to open the Service Control Manager, open the
/// driver's service, send a stop control code to it, and finally delete
/// the service registration.
///
/// # Errors
///
/// Returns an `AppError` if:
/// - The Service Control Manager cannot be opened.
/// - The service deletion fails.
///
/// Note: If the service cannot be found, the function succeeds silently.
pub fn unload_driver() -> Result<(), AppError> {
    log::debug!("Opening Service Control Manager for driver removal...");

    // SAFETY: Passing null pointers for machine name and database targets the local
    // computer and active database.
    let scm = unsafe { OpenSCManagerW(ptr::null(), ptr::null(), SC_MANAGER_ALL_ACCESS) };
    if scm.is_null() {
        return Err(win_last_error!());
    }
    let scm_handle = ScmHandle(scm);

    let service_name = windows_sys::w!("Singularity");

    // SAFETY: `scm_handle.0` is a valid SCM handle. `service_name` is a valid,
    // statically allocated null-terminated UTF-16 string.
    let service = unsafe {
        OpenServiceW(
            scm_handle.0,
            service_name,
            SERVICE_STOP | SERVICE_ALL_ACCESS,
        )
    };

    if service.is_null() {
        return Ok(());
    }
    let service_handle = ScmHandle(service);

    log::debug!("Stopping Singularity driver...");

    // SAFETY: SERVICE_STATUS is a C-compatible struct (Plain Old Data) and is safe to zero-initialize.
    let mut status: SERVICE_STATUS = unsafe { std::mem::zeroed() };

    // SAFETY: `service_handle.0` is a valid service handle. `status` is passed as a mutable
    // reference to a valid local variable, which the API will populate with status information.
    let control_result =
        unsafe { ControlService(service_handle.0, SERVICE_CONTROL_STOP, &mut status) };

    // It's a good practice to log or check if stopping fails, but kernel drivers often stop abruptly.
    if control_result == 0 {
        log::warn!("ControlService failed, attempting deletion anyway...");
    }

    log::debug!("Deleting Singularity driver registration...");

    // SAFETY: `service_handle.0` is a valid service handle mapped to the Singularity service.
    let delete_result = unsafe { DeleteService(service_handle.0) };
    if delete_result == 0 {
        return Err(win_last_error!());
    }

    Ok(())
}

/// Checks if the driver service is already registered in the Service Control Manager.
pub fn is_driver_service_registered() -> Result<bool, AppError> {
    log::debug!("Checking if Singularity driver service is registered...");

    let scm = unsafe { OpenSCManagerW(ptr::null(), ptr::null(), SC_MANAGER_ALL_ACCESS) };
    if scm.is_null() {
        return Err(win_last_error!());
    }
    let scm_handle = ScmHandle(scm);

    let service_name = windows_sys::w!("Singularity");

    let service = unsafe {
        OpenServiceW(
            scm_handle.0,
            service_name,
            SERVICE_QUERY_STATUS,
        )
    };

    if service.is_null() {
        let err = unsafe { GetLastError() };
        if err == ERROR_SERVICE_DOES_NOT_EXIST {
            return Ok(false);
        }
        return Err(win_last_error!());
    }

    Ok(true)
}

/// Retrieves the configured binary path name for the driver service.
pub fn get_service_binary_path() -> Result<String, AppError> {
    log::debug!("Retrieving Singularity driver service binary path...");

    let scm = unsafe { OpenSCManagerW(ptr::null(), ptr::null(), SC_MANAGER_ALL_ACCESS) };
    if scm.is_null() {
        return Err(win_last_error!());
    }
    let scm_handle = ScmHandle(scm);

    let service_name = windows_sys::w!("Singularity");

    let service = unsafe {
        OpenServiceW(
            scm_handle.0,
            service_name,
            SERVICE_QUERY_CONFIG,
        )
    };

    if service.is_null() {
        return Err(win_last_error!());
    }
    let service_handle = ScmHandle(service);

    let mut bytes_needed: u32 = 0;
    
    // Query required buffer size
    unsafe {
        QueryServiceConfigW(
            service_handle.0,
            ptr::null_mut(),
            0,
            &mut bytes_needed,
        );
    }

    let err = unsafe { GetLastError() };
    if err != ERROR_INSUFFICIENT_BUFFER {
        return Err(win_last_error!());
    }

    // Allocate buffer with alignment for the struct
    let mut buffer = vec![0u8; bytes_needed as usize];
    let config_ptr = buffer.as_mut_ptr() as *mut QUERY_SERVICE_CONFIGW;

    let success = unsafe {
        QueryServiceConfigW(
            service_handle.0,
            config_ptr,
            bytes_needed,
            &mut bytes_needed,
        )
    };

    if success == 0 {
        return Err(win_last_error!());
    }

    let binary_path_ptr = unsafe { (*config_ptr).lpBinaryPathName };
    if binary_path_ptr.is_null() {
        return Err(AppError::internal("Service binary path pointer is null"));
    }

    // Retrieve string length
    let mut len = 0;
    unsafe {
        while *binary_path_ptr.add(len) != 0 {
            len += 1;
        }
    }

    let wide_slice = unsafe { std::slice::from_raw_parts(binary_path_ptr, len) };
    let binary_path = String::from_utf16_lossy(wide_slice);

    Ok(binary_path)
}

/// Checks if the driver service is currently running.
pub fn is_service_running() -> Result<bool, AppError> {
    log::debug!("Checking if Singularity driver service is running...");

    let scm = unsafe { OpenSCManagerW(ptr::null(), ptr::null(), SC_MANAGER_ALL_ACCESS) };
    if scm.is_null() {
        return Err(win_last_error!());
    }
    let scm_handle = ScmHandle(scm);

    let service_name = windows_sys::w!("Singularity");

    let service = unsafe {
        OpenServiceW(
            scm_handle.0,
            service_name,
            SERVICE_QUERY_STATUS,
        )
    };

    if service.is_null() {
        return Ok(false);
    }
    let service_handle = ScmHandle(service);

    let mut status: SERVICE_STATUS = unsafe { std::mem::zeroed() };
    let success = unsafe {
        QueryServiceStatus(service_handle.0, &mut status)
    };

    if success == 0 {
        return Err(win_last_error!());
    }

    Ok(status.dwCurrentState == SERVICE_RUNNING)
}
