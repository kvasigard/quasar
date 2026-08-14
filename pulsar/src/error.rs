//! Centralized application error types and Windows API error decoding.

use std::fmt;

/// Deserialization and resolution errors encountered during ETW telemetry handling.
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
                write!(f, "process not found in system tree: pid {pid}")
            }
        }
    }
}

impl std::error::Error for HandlerError {}

/// Main error type for the Pulsar EDR agent.
#[derive(Debug)]
pub enum AppError {
    /// Represents an error returned by the Windows API.
    WindowsApi {
        /// Raw Win32 error code (`GetLastError`).
        code: u32,
        /// Human-readable description decoded via `FormatMessageW`.
        message: String,
    },

    /// Represents an error encountered during the bootstrap/initialization phase.
    Bootstrap(String),

    /// Represents telemetry payload parsing and context resolution failures.
    Handler(HandlerError),

    /// Represents internal application errors that are not directly caused by Win32.
    Internal(String),
}

impl AppError {
    /// Creates a Windows API error variant.
    ///
    /// # Arguments
    ///
    /// * `code` - Win32 error code.
    /// * `message` - Human-readable error description.
    ///
    /// # Returns
    ///
    /// An `AppError::WindowsApi` instance.
    pub fn from_win32(code: u32, message: impl Into<String>) -> Self {
        Self::WindowsApi {
            code,
            message: message.into(),
        }
    }

    /// Creates a Bootstrap error variant.
    ///
    /// # Arguments
    ///
    /// * `msg` - Bootstrap failure description.
    ///
    /// # Returns
    ///
    /// An `AppError::Bootstrap` instance.
    pub fn bootstrap(msg: impl Into<String>) -> Self {
        Self::Bootstrap(msg.into())
    }

    /// Creates an internal error variant.
    ///
    /// # Arguments
    ///
    /// * `msg` - Internal error description.
    ///
    /// # Returns
    ///
    /// An `AppError::Internal` instance.
    pub fn internal(msg: impl Into<String>) -> Self {
        Self::Internal(msg.into())
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
            Self::WindowsApi { code, message } => {
                write!(f, "windows api error {code}: {message}")
            }
            Self::Bootstrap(msg) => write!(f, "bootstrap error: {msg}"),
            Self::Handler(err) => write!(f, "telemetry handler error: {err}"),
            Self::Internal(msg) => write!(f, "internal error: {msg}"),
        }
    }
}

impl std::error::Error for AppError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Handler(err) => Some(err),
            _ => None,
        }
    }
}

/// Macro that retrieves the last Windows error code and message.
///
/// Calls `GetLastError()` and `FormatMessageW()` to build an `AppError::WindowsApi`.
#[macro_export]
macro_rules! win_last_error {
    () => {{
        use windows_sys::Win32::Foundation::GetLastError;
        use windows_sys::Win32::System::Diagnostics::Debug::{
            FORMAT_MESSAGE_FROM_SYSTEM, FORMAT_MESSAGE_IGNORE_INSERTS, FormatMessageW,
        };

        #[allow(unused_unsafe)]
        let code = unsafe { GetLastError() };

        let mut buffer: [u16; 512] = [0; 512];
        #[allow(unused_unsafe)]
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
            format!("Unknown Windows error {}", code)
        };

        $crate::error::AppError::from_win32(code, message)
    }};
}
