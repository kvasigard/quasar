//! Strongly-typed ETW sensor error definitions.

use thiserror::Error;

/// Errors encountered during ETW session configuration, startup, consumption, or teardown.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum EtwError {
    /// The NT Kernel Logger singleton lock is already acquired by another session or builder.
    #[error("The NT Kernel Logger is already active or locked by another instance")]
    KernelLoggerAlreadyActive,

    /// An ETW session was attempted to be started when it is already running.
    #[error("ETW session '{0}' is already running with an active handle")]
    SessionAlreadyRunning(String),

    /// An operation requiring an active session (such as event consumption) was called on an unstarted session.
    #[error("ETW session '{0}' has not been started")]
    SessionNotStarted(String),

    /// An underlying Windows ETW API returned a failure status code.
    #[error("Windows ETW API Error {code}: {message}")]
    WindowsApi {
        code: u32,
        message: String,
    },
}

impl EtwError {
    /// Formats a Win32 error code into a structured [`EtwError::WindowsApi`] using `FormatMessageW`.
    #[inline]
    pub fn from_win32_code(code: u32) -> Self {
        let message = crate::error::format_win32_error_message(code);
        Self::WindowsApi { code, message }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_etw_error_formatting_and_matching() {
        let err = EtwError::KernelLoggerAlreadyActive;
        assert_eq!(
            err.to_string(),
            "The NT Kernel Logger is already active or locked by another instance"
        );

        let err_session = EtwError::SessionNotStarted("TestSession".to_string());
        assert_eq!(
            err_session.to_string(),
            "ETW session 'TestSession' has not been started"
        );

        let win_err = EtwError::from_win32_code(5); // ERROR_ACCESS_DENIED
        assert!(matches!(win_err, EtwError::WindowsApi { code: 5, .. }));
    }
}
