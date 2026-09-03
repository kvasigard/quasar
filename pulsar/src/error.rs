//! Centralized application error aggregator and Windows API error decoding.

use thiserror::Error;
use crate::bootstrap::BootstrapError;
use crate::drivers::error::DriverError;
use crate::sensors::etw::error::EtwError;
use crate::state::ProcessTreeError;

/// Formats a Win32 error code into a human-readable string using `FormatMessageW`.
#[inline]
pub fn format_win32_error_message(code: u32) -> String {
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

    if len > 0 {
        String::from_utf16_lossy(&buffer[..len as usize]).trim().to_string()
    } else {
        format!("Unknown Windows error code {}", code)
    }
}

/// Central application-level error type aggregating all subsystem domain errors.
#[derive(Debug, Error)]
pub enum AppError {
    /// ETW telemetry sensor and session errors.
    #[error(transparent)]
    Etw(#[from] EtwError),

    /// Driver lifecycle and KMDF communication errors.
    #[error(transparent)]
    Driver(#[from] DriverError),

    /// Pre-flight initialization and bootstrap errors.
    #[error(transparent)]
    Bootstrap(#[from] BootstrapError),

    /// Process state tree and lineage tracking errors.
    #[error(transparent)]
    ProcessTree(#[from] ProcessTreeError),

    /// Direct Windows API errors.
    #[error("Windows API Error {code}: {message}")]
    WindowsApi { code: u32, message: String },

    /// Uncategorized internal errors.
    #[error("Internal Error: {0}")]
    Internal(String),
}

impl AppError {
    /// Creates a Windows API error variant from a raw Win32 status code.
    #[inline]
    pub fn from_win32_code(code: u32) -> Self {
        let message = format_win32_error_message(code);
        Self::WindowsApi { code, message }
    }

    /// Creates a Windows API error variant with an explicit message.
    #[inline]
    pub fn from_win32(code: u32, message: impl Into<String>) -> Self {
        Self::WindowsApi {
            code,
            message: message.into(),
        }
    }

    /// Creates a Bootstrap error variant.
    #[inline]
    pub fn bootstrap(msg: impl Into<String>) -> Self {
        Self::Internal(msg.into())
    }

    /// Creates an internal error variant.
    #[inline]
    pub fn internal(msg: impl Into<String>) -> Self {
        Self::Internal(msg.into())
    }
}

/// Macro that retrieves the thread-local last Windows error code (`GetLastError`) and formats it.
#[macro_export]
macro_rules! win_last_error {
    () => {{
        #[allow(unused_unsafe)]
        let code = unsafe { windows_sys::Win32::Foundation::GetLastError() };
        $crate::error::AppError::from_win32_code(code)
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_app_error_from_domain_errors() {
        let etw_err = EtwError::KernelLoggerAlreadyActive;
        let app_err: AppError = etw_err.into();
        assert!(matches!(app_err, AppError::Etw(EtwError::KernelLoggerAlreadyActive)));
        assert_eq!(
            app_err.to_string(),
            "The NT Kernel Logger is already active or locked by another instance"
        );

        let driver_err = DriverError::NullBinaryPath;
        let app_err: AppError = driver_err.into();
        assert!(matches!(app_err, AppError::Driver(DriverError::NullBinaryPath)));

        let boot_err = BootstrapError::NotElevated;
        let app_err: AppError = boot_err.into();
        assert!(matches!(app_err, AppError::Bootstrap(BootstrapError::NotElevated)));
    }
}
