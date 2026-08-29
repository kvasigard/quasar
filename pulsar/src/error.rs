//! Centralized application error type and Windows API error decoding.

use std::fmt;

/// Main error type for the Pulsar application.
///
/// Variants:
/// - `WindowsApi` is used for any failure originating from Win32 / NTAPI calls.
/// - `Bootstrap` is used for initialization sequence failures (e.g. driver missing, lack of admin privileges).
/// - `Internal` is used for unexpected internal states or logic errors.
#[derive(Debug)]
pub enum AppError {
    /// Represents an error returned by the Windows API.
    ///
    /// `code` is the raw Win32 error code (`GetLastError`).
    /// `message` is a human-readable description obtained via `FormatMessageW`.
    WindowsApi { code: u32, message: String },

    /// Represents an error encountered during the bootstrap/initialization phase.
    Bootstrap(String),

    /// Represents internal application errors that are not directly caused by Win32.
    Internal(String),
}

impl AppError {
    /// Creates a Windows API error variant.
    ///
    /// # Arguments
    ///
    /// * `code` - Win32 error code.
    /// * `message` - Human readable error description.
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
    /// Formats a Win32 status or error code into an AppError using FormatMessageW.
    /// Many Windows APIs return error codes directly rather than setting thread-local GetLastError.
    pub fn from_win32_code(code: u32) -> Self {
        use windows_sys::Win32::System::Diagnostics::Debug::{
            FORMAT_MESSAGE_FROM_SYSTEM, FORMAT_MESSAGE_IGNORE_INSERTS, FormatMessageW,
        };

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
            format!("Unknown Windows error {}", code)
        };

        Self::from_win32(code, message)
    }
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WindowsApi { code, message } => {
                write!(f, "Windows API Error {}: {}", code, message)
            }
            Self::Bootstrap(msg) => write!(f, "Bootstrap Error: {}", msg),
            Self::Internal(msg) => write!(f, "Internal Error: {}", msg),
        }
    }
}

impl std::error::Error for AppError {}

/// Macro that retrieves the last Windows error code and message.
///
/// Calls `GetLastError()` and decodes the message into an `AppError::WindowsApi`.
#[macro_export]
macro_rules! win_last_error {
    () => {{
        #[allow(unused_unsafe)]
        let code = unsafe { windows_sys::Win32::Foundation::GetLastError() };
        $crate::error::AppError::from_win32_code(code)
    }};
}
