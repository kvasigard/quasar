//! Centralized error taxonomy, subsystem error enums, and Windows API error decoding.

use thiserror::Error;

/// Native Windows OS error code and human-readable message.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("Win32 Error (0x{code:08X} / {code}): {message}")]
pub struct Win32Error {
    /// Raw numeric error code (`GetLastError` or NTSTATUS).
    pub code: u32,
    /// Human-readable message decoded via `FormatMessageW`.
    pub message: String,
}

impl Win32Error {
    /// Creates a new `Win32Error` from an explicit code and message.
    ///
    /// # Arguments
    ///
    /// * `code` - Win32 error code.
    /// * `message` - Error description string.
    ///
    /// # Returns
    ///
    /// An initialized [`Win32Error`].
    pub fn new(code: u32, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    /// Captures the current thread's `GetLastError()` and formats it via `FormatMessageW`.
    ///
    /// # Returns
    ///
    /// A [`Win32Error`] populated with the latest OS error.
    pub fn last() -> Self {
        use windows_sys::Win32::Foundation::GetLastError;
        use windows_sys::Win32::System::Diagnostics::Debug::{
            FormatMessageW, FORMAT_MESSAGE_FROM_SYSTEM, FORMAT_MESSAGE_IGNORE_INSERTS,
        };

        let code = unsafe { GetLastError() };
        let mut buffer: [u16; 512] = [0; 512];
        let len = unsafe {
            FormatMessageW(
                FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                std::ptr::null(),
                code,
                0,
                buffer.as_mut_ptr(),
                buffer.len() as u32,
                std::ptr::null(),
            )
        };

        let message = if len > 0 {
            String::from_utf16_lossy(&buffer[..len as usize])
                .trim()
                .to_string()
        } else {
            format!("Unknown Windows error code {}", code)
        };

        Self { code, message }
    }
}

/// Errors encountered during the pre-flight checks and bootstrap initialization sequence.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum BootstrapError {
    /// EDR process is not running with elevated Administrator privileges.
    #[error("process requires elevated Administrator privileges to initialize")]
    AdminPrivilegesRequired,
    /// Package configuration files (`.inf` or `.sys`) were not found on disk.
    #[error("driver package files (.inf/.sys) not found at: {expected_path}")]
    PackageFilesNotFound {
        /// The path where files were expected to reside.
        expected_path: String,
    },
    /// Process Protection Light (PPL-Antimalware) elevation verification failed.
    #[error("process protection level (PPL-Antimalware) elevation verification failed")]
    PplVerificationFailed,
    /// Windows Driver installation API failure (`DiInstallDriverW`).
    #[error("driver installation via DiInstallDriverW failed: {0}")]
    DriverInstallationFailed(#[from] Win32Error),
}

/// Errors encountered while interacting with the Windows Service Control Manager or KMDF device.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DriverError {
    /// Failed to open Service Control Manager database.
    #[error("failed to open Service Control Manager: {0}")]
    ScmOpenFailed(Win32Error),
    /// Failed to open existing driver service in SCM.
    #[error("failed to open service '{service_name}': {source}")]
    ServiceOpenFailed {
        /// Name of the target driver service.
        service_name: String,
        /// Underlying Win32 error.
        #[source]
        source: Win32Error,
    },
    /// Failed to create driver service in SCM.
    #[error("failed to create service '{service_name}': {source}")]
    ServiceCreateFailed {
        /// Name of the target driver service.
        service_name: String,
        /// Underlying Win32 error.
        #[source]
        source: Win32Error,
    },
    /// Failed to start driver service in SCM.
    #[error("failed to start service '{service_name}': {source}")]
    ServiceStartFailed {
        /// Name of the target driver service.
        service_name: String,
        /// Underlying Win32 error.
        #[source]
        source: Win32Error,
    },
    /// Failed to query service status or configuration.
    #[error("failed to query service: {0}")]
    ServiceQueryFailed(Win32Error),
    /// Failed to acquire handle to `\\Device\\SingularityDevice`.
    #[error("failed to open kernel device handle: {0}")]
    DeviceHandleFailed(Win32Error),
    /// IOCTL communication failed.
    #[error("driver IOCTL communication failed: {0}")]
    IoctlFailed(Win32Error),
}

/// Errors encountered while managing ETW trace sessions and consumers.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EtwError {
    /// Trace session failed to start via `StartTraceW`.
    #[error("failed to start ETW session: {0}")]
    SessionStartFailed(Win32Error),
    /// Trace session failed to stop via `ControlTraceW`.
    #[error("failed to stop ETW session: {0}")]
    SessionStopFailed(Win32Error),
    /// Trace consumer failed to open via `OpenTraceW`.
    #[error("failed to open ETW trace consumer: {0}")]
    OpenTraceFailed(Win32Error),
    /// Background trace processing failed via `ProcessTrace`.
    #[error("ETW ProcessTrace loop failed: {0}")]
    ProcessTraceFailed(Win32Error),
}

/// Deserialization and resolution errors encountered during telemetry handling.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum HandlerError {
    /// Payload buffer length is smaller than the required fixed structure header.
    #[error("payload buffer too short: expected at least {expected} bytes, got {actual}")]
    PayloadTooShort {
        /// Expected minimum length in bytes.
        expected: usize,
        /// Actual length of the received buffer in bytes.
        actual: usize,
    },
    /// Process ID does not exist in the active process tree.
    #[error("process not found in system tree: PID {0}")]
    ProcessNotFound(u32),
}

/// Central unified application error type for the Pulsar EDR agent.
#[derive(Debug, Error)]
pub enum AppError {
    /// Low-level Windows OS API failure.
    #[error("system error: {0}")]
    Win32(#[from] Win32Error),
    /// Pre-flight initialization / bootstrap failure.
    #[error("bootstrap failure: {0}")]
    Bootstrap(#[from] BootstrapError),
    /// Kernel driver or SCM communication failure.
    #[error("driver failure: {0}")]
    Driver(#[from] DriverError),
    /// ETW telemetry sensor failure.
    #[error("ETW sensor failure: {0}")]
    Etw(#[from] EtwError),
    /// Ingress handler deserialization failure.
    #[error("telemetry parser error: {0}")]
    Handler(#[from] HandlerError),
    /// Portable Executable (PE) header parser error.
    #[error("PE parser error: {0}")]
    Pe(#[from] crate::helpers::pe::PeError),
    /// Internal application logic failure.
    #[error("internal error: {0}")]
    Internal(String),
}

impl AppError {
    /// Creates a Win32 error variant.
    pub fn from_win32(code: u32, message: impl Into<String>) -> Self {
        Self::Win32(Win32Error::new(code, message))
    }

    /// Creates a generic internal error variant.
    pub fn internal(msg: impl Into<String>) -> Self {
        Self::Internal(msg.into())
    }
}

/// Macro that retrieves the last Windows error as a [`Win32Error`].
#[macro_export]
macro_rules! win_last_error {
    () => {
        $crate::error::AppError::Win32($crate::error::Win32Error::last())
    };
}
