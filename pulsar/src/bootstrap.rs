//! Application bootstrap and initialization sequence.
//!
//! This module manages the pre-flight checks and initialization tasks required
//! before the main application logic can run. This includes verifying Administrator
//! privileges, locating and loading the underlying kernel driver via INF-based
//! installation, and establishing the required Process Protection Level (PPL).

use crate::drivers::kmdf;
use crate::drivers::scm;
use crate::error::AppError;
use crate::win_last_error;
use std::env;
use std::mem;

// Import exact types and functions required by the requested signature
use windows_sys::Win32::Devices::DeviceAndDriverInstallation::{
    DIINSTALLDRIVER_FLAGS, DiInstallDriverW,
};
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, HWND};
use windows_sys::Win32::Security::{
    GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetProcessInformation, OpenProcessToken,
    PROCESS_PROTECTION_LEVEL_INFORMATION, ProcessProtectionLevelInfo,
};


/// Executes the pre-flight checks and driver initialization sequence.
///
/// This function performs the following sequence:
/// 1. Verifies that the current process is running with Administrator privileges.
/// 2. Dynamically locates both the `singularity.inf` and `singularity.sys` files.
/// 3. Checks if Singularity driver service is registered:
///    - If not registered: Installs INF and loads SCM dynamic.
///    - If registered:
///      - Checks for driver upgrades (checks if file contents of local and registered binary are identical).
///      - If upgrade is needed: unloads, installs new INF, loads SCM.
///      - If no upgrade is needed: starts the service if it was stopped.
/// 4. Connects to the KMDF driver via `\Device\SingularityDevice` (handled by client).
/// 5. Sends the initialization IOCTL containing Pulsar's current PID.
/// 6. Verifies that the OS has successfully applied the requested protection level (PPL-Antimalware).
///
/// # Errors
///
/// Returns an `AppError` if any step in the initialization sequence fails.
pub fn initialize() -> Result<(), AppError> {
    log::debug!("Starting bootstrap sequence...");

    // Check if the program is running as administrator
    log::debug!("Verifying Administrator privileges...");
    if !is_running_as_admin() {
        return Err(AppError::internal("Process must be run as Administrator."));
    }

    // Resolve the dynamic paths to both package configuration and binary files
    let (inf_path, sys_path) = resolve_package_paths()?;

    // Check if Singularity service is already registered
    let is_registered = scm::is_driver_service_registered()?;
    let mut do_install = !is_registered;

    if is_registered {
        log::debug!("Singularity driver service is already registered. Checking if upgrade is needed...");
        if let Ok(installed_binary_path) = scm::get_service_binary_path() {
            let resolved_installed_path = clean_driver_path(&installed_binary_path);
            log::debug!("Comparing local '{}' with installed driver '{}'...", sys_path, resolved_installed_path);
            
            let files_match = match (std::fs::read(&sys_path), std::fs::read(&resolved_installed_path)) {
                (Ok(local_bytes), Ok(installed_bytes)) => local_bytes == installed_bytes,
                _ => false,
            };

            if !files_match {
                log::info!("New version of driver detected. Stopping and unloading old driver service...");
                // Stop and delete the service first before installing the new version
                let _ = scm::unload_driver();
                do_install = true;
            }
        } else {
            log::warn!("Could not retrieve installed driver binary path. Safe-triggering reinstall.");
            let _ = scm::unload_driver();
            do_install = true;
        }
    }

    if do_install {
        // Securely stage and install the driver package via the Windows Driver Store
        log::debug!("Installing driver package via INF from: {}", inf_path);
        install_inf_driver(&inf_path)?;

        // Start the driver service using SCM module
        log::debug!("Loading Singularity kernel driver via SCM orchestration...");
        if let Err(e) = scm::load_driver(&sys_path) {
            return Err(AppError::internal(format!(
                "Error while starting the driver service: {e}"
            )));
        }
    } else {
        // If already registered and up-to-date, check if running. Start if stopped.
        if !scm::is_service_running()? {
            log::debug!("Starting Singularity driver service (registered but stopped)...");
            if let Err(e) = scm::load_driver(&sys_path) {
                return Err(AppError::internal(format!(
                    "Error while starting the driver service: {e}"
                )));
            }
        } else {
            log::debug!("Singularity driver service is already running.");
        }
    }

    log::debug!("Connecting to the Singularity driver...");
    // kmdf_client goes out of scope here when this function returns, and its RAII
    // Drop implementation will call CloseHandle(), detaching from the driver.
    let kmdf_client = match kmdf::Singularity::connect() {
        Ok(client) => client,
        Err(e) => {
            return Err(AppError::internal(format!(
                "Failed to connect to Singularity KMDF driver: {e}"
            )));
        }
    };

    log::debug!("Requesting PPL-Antimalware elevation from the driver...");
    let ppl_request = shared::ioctl::ChangeProcessPplLevel {
        process_id: std::process::id(), // Dynamically grab our current user-mode PID
        level: 0x31,                    // PPL-Antimalware (Signer: 0x3 | Type: 0x1)
    };

    if let Err(e) = kmdf_client.send(&ppl_request) {
        return Err(AppError::internal(format!(
            "Failed to acquire PPL privileges: {e}"
        )));
    }

    // Verify applied Process Protection Level (PPL)
    log::debug!("Verifying applied Process Protection Level...");
    if !is_ppl_antimalware() {
        return Err(AppError::internal(
            "Failed to verify PPL-Antimalware token status.",
        ));
    }

    Ok(())
}

/// Helper function to normalize/clean the service binary path.
fn clean_driver_path(path: &str) -> String {
    let mut cleaned = path.trim().to_string();
    
    // Remote driver path prefix commonly used by SCM
    if cleaned.starts_with("\\??\\") {
        cleaned = cleaned[4..].to_string();
    }
    
    // Strip quotes
    cleaned = cleaned.trim_matches('"').to_string();

    let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
    cleaned = cleaned.replace("\\SystemRoot\\", &format!("{}\\", system_root));
    cleaned = cleaned.replace("\\systemroot\\", &format!("{}\\", system_root));
    cleaned = cleaned.replace("%SystemRoot%", &system_root);
    cleaned = cleaned.replace("%systemroot%", &system_root);
    cleaned
}

/// Securely installs an INF-based driver package into the Windows Driver Store.
fn install_inf_driver(inf_path: &str) -> Result<(), AppError> {
    // Convert INF path to null-terminated UTF-16 wide string
    let mut wide_inf: Vec<u16> = inf_path.encode_utf16().collect();
    wide_inf.push(0);

    let mut need_reboot: i32 = 0i32;

    // Flags: 0 or 0x00000002 (DIIRF_FORCE_INF_INSTALL) to force reinstallation if required
    let flags: DIINSTALLDRIVER_FLAGS = 0;

    // SAFETY:
    // - `hwndparent` is passed as 0 (NULL handle) since installation runs headlessly.
    // - `infpath` points to a valid, heap-allocated, null-terminated array of wide characters.
    // - `needreboot` is passed as a valid mutable pointer to a stack-allocated BOOL integer.
    let success =
        unsafe { DiInstallDriverW(0 as HWND, wide_inf.as_ptr(), flags, &mut need_reboot) };

    // DiInstallDriverW returns non-zero (TRUE) on success, or 0 (FALSE) on failure.
    if success == 0 {
        return Err(win_last_error!());
    }

    if need_reboot != 0 {
        log::warn!("Windows indicates a system reboot is required to finish driver installation.");
    }

    Ok(())
}

/// Locates both the `singularity.inf` and `singularity.sys` files relative to the executable path.
///
/// Searches for the installation package first in the same directory as the executable,
/// and then falls back to a `singularity_package` subdirectory.
///
/// # Errors
///
/// Returns an `AppError` if the executable path cannot be determined or if
/// the required package components cannot be paired together in the same target location.
fn resolve_package_paths() -> Result<(String, String), AppError> {
    let exe_path = env::current_exe()
        .map_err(|e| AppError::internal(format!("Failed to get executable path: {}", e)))?;

    let exe_dir = exe_path
        .parent()
        .ok_or_else(|| AppError::internal("Executable path has no parent directory"))?;

    let inf_name = "singularity.inf";
    let sys_name = "singularity.sys";

    // Checks if the files are loose in the same directory as the executable
    let direct_inf = exe_dir.join(inf_name);
    let direct_sys = exe_dir.join(sys_name);
    if direct_inf.exists() && direct_sys.exists() {
        return Ok((
            direct_inf.to_string_lossy().into_owned(),
            direct_sys.to_string_lossy().into_owned(),
        ));
    }

    // Checks if the files are inside the structured package subdirectory
    let nested_dir = exe_dir.join("singularity_package");
    let nested_inf = nested_dir.join(inf_name);
    let nested_sys = nested_dir.join(sys_name);
    if nested_inf.exists() && nested_sys.exists() {
        return Ok((
            nested_inf.to_string_lossy().into_owned(),
            nested_sys.to_string_lossy().into_owned(),
        ));
    }

    Err(AppError::internal(format!(
        "Could not find a valid deployment pairing of '{}' and '{}' in the executable directory or 'singularity_package\\' subdirectory.",
        inf_name, sys_name
    )))
}

/// Checks if the current process token has the elevation flag set.
///
/// Returns `true` if the process is running as an Administrator, otherwise `false`.
fn is_running_as_admin() -> bool {
    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();

        // SAFETY: `GetCurrentProcess()` returns a pseudo-handle that is always valid for the
        // current process. Passing a mutable reference to `token` is safe for receiving the handle.
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }

        // SAFETY: `TOKEN_ELEVATION` is a plain C-struct containing only primitive integers.
        // Zero-initializing it is safe and explicitly expected by Win32 APIs.
        let mut elevation: TOKEN_ELEVATION = mem::zeroed();
        let mut size = mem::size_of::<TOKEN_ELEVATION>() as u32;

        // SAFETY:
        // - `token` is a valid handle successfully acquired with `TOKEN_QUERY` access rights.
        // - `elevation` is a valid, correctly-sized buffer cast to `*mut c_void`.
        // - `size` correctly reflects the buffer size.
        let success = GetTokenInformation(
            token,
            TokenElevation,
            &mut elevation as *mut _ as *mut _,
            size,
            &mut size,
        );

        // SAFETY: `token` is guaranteed to be a valid handle at this point.
        CloseHandle(token);

        success != 0 && elevation.TokenIsElevated != 0
    }
}

/// Queries the OS to verify if the current process has the expected PPL level.
///
/// Returns `true` if the process is protected as PPL-Antimalware (represented as
/// `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` = 3 in user-mode API), otherwise `false`.
fn is_ppl_antimalware() -> bool {
    unsafe {
        // SAFETY: `PROCESS_PROTECTION_LEVEL_INFORMATION` is a plain C-struct.
        // Zero-initializing it is safe and provides a clean buffer for the OS.
        let mut ppl_info: PROCESS_PROTECTION_LEVEL_INFORMATION = mem::zeroed();

        // SAFETY:
        // - `GetCurrentProcess()` safely returns the pseudo-handle for the current process.
        // - `ProcessProtectionLevelInfo` is the correct info class for this struct.
        // - `ppl_info` is passed as a valid mutable pointer with its exact size.
        let success = GetProcessInformation(
            GetCurrentProcess(),
            ProcessProtectionLevelInfo,
            &mut ppl_info as *mut _ as *mut _,
            mem::size_of::<PROCESS_PROTECTION_LEVEL_INFORMATION>() as u32,
        );

        if success == 0 {
            return false;
        }

        // Note: The user-mode GetProcessInformation API returns an enum value from 0 to 7.
        // Value 3 corresponds to PROTECTION_LEVEL_ANTIMALWARE_LIGHT.
        // This is different from the raw kernel PS_PROTECTION byte (0x31) that the driver writes.
        let level = ppl_info.ProtectionLevel;
        log::debug!("User-mode process protection level returned: {}", level);

        level == 3
    }
}
