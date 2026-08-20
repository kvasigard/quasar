//! Centralized error taxonomy, subsystem error enums, and Windows API error decoding.

use std::fmt;

/// Native Windows OS error code and human-readable message.
#[derive(Debug, Clone, PartialEq, Eq)]
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

impl fmt::Display for Win32Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Win32 Error (0x{:08X} / {}): {}", self.code, self.code, self.message)
    }
}

impl std::error::Error for Win32Error {}

/// Errors encountered during the pre-flight checks and bootstrap initialization sequence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootstrapError {
    /// EDR process is not running with elevated Administrator privileges.
    AdminPrivilegesRequired,
    /// Package configuration files (`.inf` or `.sys`) were not found on disk.
    PackageFilesNotFound {
        /// The path where files were expected to reside.
        expected_path: String,
    },
    /// Process Protection Light (PPL-Antimalware) elevation verification failed.
    PplVerificationFailed,
    /// Windows Driver installation API failure (`DiInstallDriverW`).
    DriverInstallationFailed(Win32Error),
}

impl fmt::Display for BootstrapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AdminPrivilegesRequired => {
                write!(f, "process requires elevated Administrator privileges to initialize")
            }
            Self::PackageFilesNotFound { expected_path } => {
                write!(f, "driver package files (.inf/.sys) not found at: {expected_path}")
            }
            Self::PplVerificationFailed => {
                write!(f, "process protection level (PPL-Antimalware) elevation verification failed")
            }
            Self::DriverInstallationFailed(err) => {
                write!(f, "driver installation via DiInstallDriverW failed: {err}")
            }
        }
    }
}

impl std::error::Error for BootstrapError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::DriverInstallationFailed(err) => Some(err),
            _ => None,
        }
    }
}

/// Errors encountered while interacting with the Windows Service Control Manager or KMDF device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DriverError {
    /// Failed to open Service Control Manager database.
    ScmOpenFailed(Win32Error),
    /// Failed to open existing driver service in SCM.
    ServiceOpenFailed {
        /// Name of the target driver service.
        service_name: String,
        /// Underlying Win32 error.
        source: Win32Error,
    },
    /// Failed to create driver service in SCM.
    ServiceCreateFailed {
        /// Name of the target driver service.
        service_name: String,
        /// Underlying Win32 error.
        source: Win32Error,
    },
    /// Failed to start driver service in SCM.
    ServiceStartFailed {
        /// Name of the target driver service.
        service_name: String,
        /// Underlying Win32 error.
        source: Win32Error,
    },
    /// Failed to query service status or configuration.
    ServiceQueryFailed(Win32Error),
    /// Failed to acquire handle to `\Device\SingularityDevice`.
    DeviceHandleFailed(Win32Error),
    /// IOCTL communication failed.
    IoctlFailed(Win32Error),
}

impl fmt::Display for DriverError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ScmOpenFailed(err) => write!(f, "failed to open Service Control Manager: {err}"),
            Self::ServiceOpenFailed { service_name, source } => {
                write!(f, "failed to open service '{service_name}': {source}")
            }
            Self::ServiceCreateFailed { service_name, source } => {
                write!(f, "failed to create service '{service_name}': {source}")
            }
            Self::ServiceStartFailed { service_name, source } => {
                write!(f, "failed to start service '{service_name}': {source}")
            }
            Self::ServiceQueryFailed(err) => write!(f, "failed to query service: {err}"),
            Self::DeviceHandleFailed(err) => write!(f, "failed to open kernel device handle: {err}"),
            Self::IoctlFailed(err) => write!(f, "driver IOCTL communication failed: {err}"),
        }
    }
}

impl std::error::Error for DriverError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ScmOpenFailed(err)
            | Self::ServiceQueryFailed(err)
            | Self::DeviceHandleFailed(err)
            | Self::IoctlFailed(err) => Some(err),
            Self::ServiceOpenFailed { source, .. }
            | Self::ServiceCreateFailed { source, .. }
            | Self::ServiceStartFailed { source, .. } => Some(source),
        }
    }
}

/// Errors encountered while managing ETW trace sessions and consumers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EtwError {
    /// Trace session failed to start via `StartTraceW`.
    SessionStartFailed(Win32Error),
    /// Trace session failed to stop via `ControlTraceW`.
    SessionStopFailed(Win32Error),
    /// Trace consumer failed to open via `OpenTraceW`.
    OpenTraceFailed(Win32Error),
    /// Background trace processing failed via `ProcessTrace`.
    ProcessTraceFailed(Win32Error),
}

impl fmt::Display for EtwError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SessionStartFailed(err) => write!(f, "failed to start ETW session: {err}"),
            Self::SessionStopFailed(err) => write!(f, "failed to stop ETW session: {err}"),
            Self::OpenTraceFailed(err) => write!(f, "failed to open ETW trace consumer: {err}"),
            Self::ProcessTraceFailed(err) => write!(f, "ETW ProcessTrace loop failed: {err}"),
        }
    }
}

impl std::error::Error for EtwError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::SessionStartFailed(err)
            | Self::SessionStopFailed(err)
            | Self::OpenTraceFailed(err)
            | Self::ProcessTraceFailed(err) => Some(err),
        }
    }
}

/// Deserialization and resolution errors encountered during telemetry handling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandlerError {
    /// Payload buffer length is smaller than the required fixed structure header.
    PayloadTooShort {
        /// Expected minimum length in bytes.
        expected: usize,
        /// Actual length of the received buffer in bytes.
        actual: usize,
    },
    /// Process ID does not exist in the active process tree.
    ProcessNotFound(u32),
}

impl fmt::Display for HandlerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PayloadTooShort { expected, actual } => {
                write!(
                    f,
                    "payload buffer too short: expected at least {expected} bytes, got {actual}"
                )
            }
            Self::ProcessNotFound(pid) => {
                write!(f, "process not found in system tree: PID {pid}")
            }
        }
    }
}

impl std::error::Error for HandlerError {}

/// Central unified application error type for the Pulsar EDR agent.
#[derive(Debug)]
pub enum AppError {
    /// Low-level Windows OS API failure.
    Win32(Win32Error),
    /// Pre-flight initialization / bootstrap failure.
    Bootstrap(BootstrapError),
    /// Kernel driver or SCM communication failure.
    Driver(DriverError),
    /// ETW telemetry sensor failure.
    Etw(EtwError),
    /// Ingress handler deserialization failure.
    Handler(HandlerError),
    /// Internal application logic failure.
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

impl From<Win32Error> for AppError {
    fn from(err: Win32Error) -> Self {
        Self::Win32(err)
    }
}

impl From<BootstrapError> for AppError {
    fn from(err: BootstrapError) -> Self {
        Self::Bootstrap(err)
    }
}

impl From<DriverError> for AppError {
    fn from(err: DriverError) -> Self {
        Self::Driver(err)
    }
}

impl From<EtwError> for AppError {
    fn from(err: EtwError) -> Self {
        Self::Etw(err)
    }
}

impl From<HandlerError> for AppError {
    fn from(err: HandlerError) -> Self {
        Self::Handler(err)
    }
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Win32(err) => write!(f, "system error: {err}"),
            Self::Bootstrap(err) => write!(f, "bootstrap failure: {err}"),
            Self::Driver(err) => write!(f, "driver failure: {err}"),
            Self::Etw(err) => write!(f, "ETW sensor failure: {err}"),
            Self::Handler(err) => write!(f, "telemetry parser error: {err}"),
            Self::Internal(msg) => write!(f, "internal error: {msg}"),
        }
    }
}

impl std::error::Error for AppError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Win32(err) => Some(err),
            Self::Bootstrap(err) => Some(err),
            Self::Driver(err) => Some(err),
            Self::Etw(err) => Some(err),
            Self::Handler(err) => Some(err),
            Self::Internal(_) => None,
        }
    }
}

/// Macro that retrieves the last Windows error as a [`Win32Error`].
#[macro_export]
macro_rules! win_last_error {
    () => {
        $crate::error::AppError::Win32($crate::error::Win32Error::last())
    };
}
