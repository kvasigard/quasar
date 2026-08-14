//! Provides functionality for managing Windows kernel drivers via the Service Control Manager.
//!
//! Interacts with the Windows SCM to register, start, stop, query, and delete kernel drivers dynamically.

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
/// Automatically closes the underlying handle when dropped to prevent resource leaks.
struct ScmHandle(*mut c_void);

impl Drop for ScmHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: The handle is guaranteed valid and owned by this struct.
            unsafe {
                CloseServiceHandle(self.0);
            }
        }
    }
}

/// Registers and starts the kernel driver located at the specified path.
///
/// # Arguments
///
/// * `driver_path` - The absolute filesystem path to the `.sys` driver binary.
///
/// # Returns
///
/// `Ok(())` on successful start or if already running, otherwise `Err(AppError)`.
///
/// # Errors
///
/// Returns `AppError::WindowsApi` if opening SCM, creating service, or starting service fails.
pub fn load_driver(driver_path: &str) -> Result<(), AppError> {
    log::debug!(target: "scm", "Opening Service Control Manager...");

    // SAFETY: Passing null pointers for machine name and database name targets the
    // local machine and the ServicesActive database.
    let scm = unsafe { OpenSCManagerW(ptr::null(), ptr::null(), SC_MANAGER_ALL_ACCESS) };
    if scm.is_null() {
        return Err(win_last_error!());
    }
    let scm_handle = ScmHandle(scm);

    let service_name = windows_sys::w!("Singularity");

    // SAFETY: `scm_handle.0` is a valid handle to the SCM. `service_name` is a null-terminated UTF-16 string.
    let service = unsafe {
        OpenServiceW(
            scm_handle.0,
            service_name,
            SERVICE_START | SERVICE_ALL_ACCESS,
        )
    };

    let service_handle = if service.is_null() {
        // SAFETY: GetLastError returns the thread-local error code.
        let err = unsafe { GetLastError() };
        if err != ERROR_SERVICE_DOES_NOT_EXIST {
            return Err(win_last_error!());
        }

        log::info!(target: "scm", "Registering Singularity driver service...");

        // Encode to null-terminated UTF-16 wide string for Win32 API consumption
        let mut wide_path: Vec<u16> = driver_path.encode_utf16().collect();
        wide_path.push(0);

        // SAFETY:
        // - `scm_handle.0` is a valid SCM handle.
        // - `service_name` and `wide_path` are valid null-terminated UTF-16 wide strings.
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

    log::debug!(target: "scm", "Starting Singularity driver...");

    // SAFETY: `service_handle.0` is a valid service handle.
    let start_result = unsafe { StartServiceW(service_handle.0, 0, ptr::null()) };

    if start_result == 0 {
        let err = unsafe { GetLastError() };
        if err != ERROR_SERVICE_ALREADY_RUNNING {
            return Err(win_last_error!());
        }
    }

    Ok(())
}

/// Stops and unregisters the currently loaded kernel driver from SCM.
///
/// # Returns
///
/// `Ok(())` on successful deletion (or if service does not exist), otherwise `Err(AppError)`.
///
/// # Errors
///
/// Returns `AppError::WindowsApi` if SCM access or service deletion fails.
pub fn unload_driver() -> Result<(), AppError> {
    log::debug!(target: "scm", "Opening Service Control Manager for driver removal...");

    // SAFETY: Target local computer and active database.
    let scm = unsafe { OpenSCManagerW(ptr::null(), ptr::null(), SC_MANAGER_ALL_ACCESS) };
    if scm.is_null() {
        return Err(win_last_error!());
    }
    let scm_handle = ScmHandle(scm);

    let service_name = windows_sys::w!("Singularity");

    // SAFETY: `scm_handle.0` is a valid SCM handle.
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

    log::debug!(target: "scm", "Stopping Singularity driver service...");

    // SAFETY: SERVICE_STATUS is a plain C struct safe to zero-initialize.
    let mut status: SERVICE_STATUS = unsafe { std::mem::zeroed() };

    let control_result =
        unsafe { ControlService(service_handle.0, SERVICE_CONTROL_STOP, &mut status) };

    if control_result == 0 {
        log::warn!(target: "scm", "ControlService stop request failed or service already stopped. Proceeding with deletion.");
    }

    log::debug!(target: "scm", "Deleting Singularity driver service registration...");

    let delete_result = unsafe { DeleteService(service_handle.0) };
    if delete_result == 0 {
        return Err(win_last_error!());
    }

    Ok(())
}

/// Checks if the driver service is already registered in the Service Control Manager.
///
/// # Returns
///
/// `Ok(true)` if registered, `Ok(false)` if not found, or `Err(AppError)` on failure.
///
/// # Errors
///
/// Returns `AppError::WindowsApi` if SCM cannot be opened.
pub fn is_driver_service_registered() -> Result<bool, AppError> {
    log::debug!(target: "scm", "Checking if Singularity driver service is registered...");

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
///
/// # Returns
///
/// `Ok(String)` containing the registered binary path, or `Err(AppError)` on failure.
///
/// # Errors
///
/// Returns `AppError::WindowsApi` or `AppError::Internal` if query fails.
pub fn get_service_binary_path() -> Result<String, AppError> {
    log::debug!(target: "scm", "Retrieving Singularity driver service binary path...");

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

/// Checks if the driver service is currently in the `SERVICE_RUNNING` state.
///
/// # Returns
///
/// `Ok(true)` if running, `Ok(false)` if stopped or not found, or `Err(AppError)` on failure.
///
/// # Errors
///
/// Returns `AppError::WindowsApi` if service status query fails.
pub fn is_service_running() -> Result<bool, AppError> {
    log::debug!(target: "scm", "Checking if Singularity driver service is running...");

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
