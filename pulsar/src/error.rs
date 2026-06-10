//! Centralized application error type.
//!
//! This module defines the primary error enum used across the entire
//! application. It provides idiomatic Rust error handling while also
//! supporting Windows API failures through windows-rs.

use std::fmt;

/// Main error type for the application.
///
/// This enum intentionally keeps the number of variants small.
/// - `WindowsApi` is used for any failure originating from Win32 calls.
/// - `Bootstrap` is used for initialization sequence failures (e.g., driver missing, privileges).
/// - `Internal` is used for unexpected states or logic errors inside the app.
#[derive(Debug)]
pub enum AppError {
    /// Represents an error returned by the Windows API.
    ///
    /// `code` is the raw Win32 error code (GetLastError).
    /// `message` is a human-readable description obtained via FormatMessageW.
    WindowsApi { code: u32, message: String },

    /// Represents an error encountered during the bootstrap/initialization phase.
    Bootstrap(String),

    /// Represents internal application errors that are not related to Win32.
    ///
    /// This is a flexible catch‑all for logic errors, invalid states,
    /// or any other unexpected condition.
    Internal(String),
}

impl AppError {
    /// Creates a Windows API error variant.
    ///
    /// This is typically used together with the `win_last_error!()` macro.
    pub fn from_win32(code: u32, message: impl Into<String>) -> Self {
        Self::WindowsApi {
            code,
            message: message.into(),
        }
    }

    /// Creates a Bootstrap error variant.
    pub fn bootstrap(msg: impl Into<String>) -> Self {
        Self::Bootstrap(msg.into())
    }

    /// Creates an internal error variant.
    pub fn internal(msg: impl Into<String>) -> Self {
        Self::Internal(msg.into())
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
/// This macro calls:
/// - `GetLastError()` to obtain the raw Win32 error code.
/// - `FormatMessageW()` to convert it into a readable string.
///
/// It returns an `AppError::WindowsApi`.
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
