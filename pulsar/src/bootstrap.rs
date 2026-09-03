//! Application bootstrap and initialization sequence.
//!
//! This module manages pre-flight checks and initialization tasks required
//! before the main application logic can run. This includes verifying Administrator
//! privileges, locating and loading the underlying kernel driver via INF-based
//! installation, and establishing the required Process Protection Level (PPL).

use std::env;
use std::mem;
use thiserror::Error;

use crate::drivers::error::DriverError;
use crate::drivers::kmdf;
use crate::drivers::scm;

use windows_sys::Win32::Devices::DeviceAndDriverInstallation::{
    DIINSTALLDRIVER_FLAGS, DiInstallDriverW,
};
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, HWND};
use windows_sys::Win32::Security::{
    GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetProcessInformation, OpenProcessToken,
    PROCESS_PROTECTION_LEVEL_INFORMATION, ProcessProtectionLevelInfo,
};

/// Errors encountered during the pre-flight bootstrap and initialization sequence.
#[derive(Debug, Error)]
pub enum BootstrapError {
    /// The process is running without Administrator privileges.
    #[error("Process must be executed with elevated Administrator privileges")]
    NotElevated,

    /// Could not locate the driver package files (`singularity.inf` / `singularity.sys`).
    #[error("Could not locate driver package pairing '{inf}' and '{sys}' in executable directory or 'singularity_package\\'")]
    PackageNotFound {
        inf: String,
        sys: String,
    },

    /// Current executable directory path resolution failed.
    #[error("Failed to resolve current executable directory: {0}")]
    ExecutablePath(String),

    /// Kernel driver installation, SCM registration, or loading failed.
    #[error("Kernel driver bootstrap failed: {0}")]
    Driver(#[from] DriverError),

    /// Driver connection or IOCTL request for PPL elevation failed.
    #[error("Failed to acquire PPL privileges from driver: {0}")]
    PplElevation(#[source] DriverError),

    /// Process Protection Level verification failed (process is not running as PPL-Antimalware).
    #[error("Failed to verify PPL-Antimalware protection level (expected level 3)")]
    PplVerificationFailed,

    /// A Win32 setup API call (e.g. `DiInstallDriverW`) failed.
    #[error("Windows Setup API Error {code}: {message}")]
    WindowsApi {
        code: u32,
        message: String,
    },
}

impl BootstrapError {
    /// Formats a Win32 error code into a structured [`BootstrapError::WindowsApi`] using `FormatMessageW`.
    #[inline]
    pub fn from_win32_code(code: u32) -> Self {
        let message = crate::error::format_win32_error_message(code);
        Self::WindowsApi { code, message }
    }
}

/// Executes the pre-flight checks and driver initialization sequence.
///
/// Sequence:
/// 1. Verifies that the current process is running with Administrator privileges.
/// 2. Dynamically locates both the `singularity.inf` and `singularity.sys` package files.
/// 3. Checks if the Singularity driver service is registered:
///    - If not registered: Installs INF into Driver Store and starts service via SCM.
///    - If registered: Compares binary hashes/bytes for upgrades, reloading if changed.
/// 4. Connects to the KMDF driver via `\Device\SingularityDevice`.
/// 5. Sends the initialization IOCTL containing Pulsar's current PID for PPL elevation.
/// 6. Verifies that the OS has applied the requested protection level (`PPL-Antimalware`).
///
/// # Returns
///
/// `Ok(())` on successful bootstrap completion, or `Err(BootstrapError)` on failure.
///
/// # Errors
///
/// Returns a [`BootstrapError`] if non-elevated, if package files cannot be located,
/// if driver loading fails, or if PPL elevation cannot be confirmed.
pub fn initialize() -> Result<(), BootstrapError> {
    log::debug!(target: "bootstrap", "Starting bootstrap sequence...");

    // Check if the program is running as administrator
    log::debug!(target: "bootstrap", "Verifying Administrator privileges...");
    if !is_running_as_admin() {
        return Err(BootstrapError::NotElevated);
    }

    // Resolve the dynamic paths to both package configuration and binary files
    let (inf_path, sys_path) = resolve_package_paths()?;

    // Check if Singularity service is already registered
    let is_registered = scm::is_driver_service_registered()?;
    let mut do_install = !is_registered;

    if is_registered {
        log::debug!(target: "bootstrap", "Singularity driver service is already registered. Checking if upgrade is needed...");
        if let Ok(installed_binary_path) = scm::get_service_binary_path() {
            let resolved_installed_path = clean_driver_path(&installed_binary_path);
            log::debug!(
                target: "bootstrap",
                "Comparing local '{}' with installed driver '{}'...",
                sys_path,
                resolved_installed_path
            );

            let files_match = match (std::fs::read(&sys_path), std::fs::read(&resolved_installed_path)) {
                (Ok(local_bytes), Ok(installed_bytes)) => local_bytes == installed_bytes,
                _ => false,
            };

            if !files_match {
                log::info!(target: "bootstrap", "New version of driver detected. Stopping and unloading old driver service...");
                let _ = scm::unload_driver();
                do_install = true;
            }
        } else {
            log::warn!(target: "bootstrap", "Could not retrieve installed driver binary path. Safe-triggering reinstall.");
            let _ = scm::unload_driver();
            do_install = true;
        }
    }

    if do_install {
        // Securely stage and install the driver package via the Windows Driver Store
        log::debug!(target: "bootstrap", "Installing driver package via INF from: {}", inf_path);
        install_inf_driver(&inf_path)?;

        // Start the driver service using SCM module
        log::debug!(target: "bootstrap", "Loading Singularity kernel driver via SCM orchestration...");
        scm::load_driver(&sys_path)?;
    } else {
        // If already registered and up-to-date, check if running. Start if stopped.
        if !scm::is_service_running()? {
            log::debug!(target: "bootstrap", "Starting Singularity driver service (registered but stopped)...");
            scm::load_driver(&sys_path)?;
        } else {
            log::debug!(target: "bootstrap", "Singularity driver service is already running.");
        }
    }

    log::debug!(target: "bootstrap", "Connecting to the Singularity driver...");
    // kmdf_client goes out of scope here when this function returns, and its RAII
    // Drop implementation will call CloseHandle(), detaching from the driver.
    let kmdf_client = kmdf::Singularity::connect().map_err(BootstrapError::PplElevation)?;

    log::debug!(target: "bootstrap", "Requesting PPL-Antimalware elevation from the driver...");
    let ppl_request = shared::ioctl::ChangeProcessPplLevel {
        process_id: std::process::id(),
        level: 0x31, // PPL-Antimalware (Signer: 0x3 | Type: 0x1)
    };

    kmdf_client
        .send(&ppl_request)
        .map_err(BootstrapError::PplElevation)?;

    // Verify applied Process Protection Level (PPL)
    log::debug!(target: "bootstrap", "Verifying applied Process Protection Level...");
    if !is_ppl_antimalware() {
        return Err(BootstrapError::PplVerificationFailed);
    }

    log::info!(target: "bootstrap", "Bootstrap successful. Running with PPL-Antimalware protection.");
    Ok(())
}

/// Normalizes and cleans service binary paths by expanding system root macros and stripping prefixes.
///
/// # Arguments
///
/// * `path` - Raw service binary path string from SCM query.
///
/// # Returns
///
/// The cleaned absolute filesystem path.
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

/// Installs an INF-based driver package into the Windows Driver Store using `DiInstallDriverW`.
///
/// # Arguments
///
/// * `inf_path` - Filesystem path to `singularity.inf`.
///
/// # Returns
///
/// `Ok(())` on success, or `Err(BootstrapError)` if installation fails.
///
/// # Errors
///
/// Returns [`BootstrapError::WindowsApi`] if `DiInstallDriverW` returns zero.
fn install_inf_driver(inf_path: &str) -> Result<(), BootstrapError> {
    let mut wide_inf: Vec<u16> = inf_path.encode_utf16().collect();
    wide_inf.push(0);

    let mut need_reboot: i32 = 0i32;
    let flags: DIINSTALLDRIVER_FLAGS = 0;

    // SAFETY:
    // - `hwndparent` is 0 (NULL handle) since installation runs headlessly.
    // - `infpath` points to a null-terminated UTF-16 wide character array.
    // - `needreboot` is a valid pointer to a stack-allocated BOOL.
    let success =
        unsafe { DiInstallDriverW(0 as HWND, wide_inf.as_ptr(), flags, &mut need_reboot) };

    if success == 0 {
        let err = unsafe { GetLastError() };
        return Err(BootstrapError::from_win32_code(err));
    }

    if need_reboot != 0 {
        log::warn!(target: "bootstrap", "Windows indicates a system reboot is required to finish driver installation.");
    }

    Ok(())
}

/// Locates both `singularity.inf` and `singularity.sys` relative to the executable path.
///
/// Searches first in the executable directory, then in a `singularity_package` subdirectory.
///
/// # Returns
///
/// `Ok((inf_path, sys_path))` if both files are found, or `Err(BootstrapError)` otherwise.
///
/// # Errors
///
/// Returns [`BootstrapError::ExecutablePath`] or [`BootstrapError::PackageNotFound`].
fn resolve_package_paths() -> Result<(String, String), BootstrapError> {
    let exe_path = env::current_exe()
        .map_err(|e| BootstrapError::ExecutablePath(format!("Failed to get executable path: {}", e)))?;

    let exe_dir = exe_path
        .parent()
        .ok_or_else(|| BootstrapError::ExecutablePath("Executable path has no parent directory".into()))?;

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

    Err(BootstrapError::PackageNotFound {
        inf: inf_name.to_string(),
        sys: sys_name.to_string(),
    })
}

/// Checks if the current process token has the Administrator elevation flag set.
///
/// # Returns
///
/// `true` if elevated with Administrator token, `false` otherwise.
fn is_running_as_admin() -> bool {
    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();

        // SAFETY: `GetCurrentProcess()` returns a valid pseudo-handle.
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }

        let mut elevation: TOKEN_ELEVATION = mem::zeroed();
        let mut size = mem::size_of::<TOKEN_ELEVATION>() as u32;

        let success = GetTokenInformation(
            token,
            TokenElevation,
            &mut elevation as *mut _ as *mut _,
            size,
            &mut size,
        );

        CloseHandle(token);

        success != 0 && elevation.TokenIsElevated != 0
    }
}

/// Queries the OS to verify if the current process has `PPL-Antimalware` protection.
///
/// # Returns
///
/// `true` if protected as `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` (value 3), `false` otherwise.
fn is_ppl_antimalware() -> bool {
    unsafe {
        let mut ppl_info: PROCESS_PROTECTION_LEVEL_INFORMATION = mem::zeroed();

        let success = GetProcessInformation(
            GetCurrentProcess(),
            ProcessProtectionLevelInfo,
            &mut ppl_info as *mut _ as *mut _,
            mem::size_of::<PROCESS_PROTECTION_LEVEL_INFORMATION>() as u32,
        );

        if success == 0 {
            return false;
        }

        let level = ppl_info.ProtectionLevel;
        log::debug!(target: "bootstrap", "User-mode process protection level returned: {}", level);

        level == 3
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bootstrap_error_formatting() {
        let err = BootstrapError::NotElevated;
        assert_eq!(
            err.to_string(),
            "Process must be executed with elevated Administrator privileges"
        );

        let err_pkg = BootstrapError::PackageNotFound {
            inf: "singularity.inf".to_string(),
            sys: "singularity.sys".to_string(),
        };
        assert!(err_pkg.to_string().contains("singularity.inf"));
    }

    /// Validates SCM binary path normalization by stripping NT DOS device prefixes, enclosing quotes, and expanding SystemRoot variables.
    /// Mandatory to ensure driver upgrade comparison checks accurately match local staged driver binaries against active SCM service registrations.
    #[test]
    fn test_clean_driver_path_normalization() {
        let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());

        let scm_raw = r#"\??\C:\Windows\System32\drivers\singularity.sys"#;
        assert_eq!(clean_driver_path(scm_raw), r#"C:\Windows\System32\drivers\singularity.sys"#);

        let quoted_raw = r#""C:\Program Files\Quasar\singularity.sys""#;
        assert_eq!(clean_driver_path(quoted_raw), r#"C:\Program Files\Quasar\singularity.sys"#);

        let macro_raw = r#"\SystemRoot\System32\drivers\singularity.sys"#;
        assert_eq!(
            clean_driver_path(macro_raw),
            format!(r#"{}\System32\drivers\singularity.sys"#, system_root)
        );
    }
}
