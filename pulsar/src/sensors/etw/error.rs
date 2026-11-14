//! Strongly-typed error definitions for the ETW sensor subsystem.
//!
//! [`EtwError`] normalizes Win32 status codes returned by `StartTraceW`, `ControlTraceW`,
//! `EnableTraceEx2`, `TraceSetInformation`, and `OpenTraceW`/`ProcessTrace` alongside
//! state-machine invariant violations (such as starting a session twice or attempting to
//! consume from an unstarted session) and FFI callback panic containment.

use thiserror::Error;

/// Errors encountered during ETW session configuration, startup, real-time consumption, or teardown.
///
/// Each variant distinguishes between a caller lifecycle violation, a contained panic across
/// the Win32 `extern "system"` callback boundary, or an OS-level Win32 API failure.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum EtwError {
    /// Produced when [`KernelSessionBuilder::build`](super::KernelSessionBuilder::build) is called
    /// while another [`KernelSession`](super::KernelSession) already holds the process-wide
    /// `NtKernelGuard` lock.
    #[error("The NT Kernel Logger is already active or locked by another instance")]
    KernelLoggerAlreadyActive,

    /// Produced when [`EtwSession::start`](super::EtwSession::start) is invoked on a session
    /// that already owns an active `CONTROLTRACE_HANDLE`.
    #[error("ETW session '{0}' is already running with an active handle")]
    SessionAlreadyRunning(String),

    /// Produced when an operation requiring an active kernel trace session (such as
    /// [`EtwSession::consume_with_router`](super::EtwSession::consume_with_router),
    /// `query_statistics`, or `flush`) is called before [`EtwSession::start`](super::EtwSession::start).
    #[error("ETW session '{0}' has not been started")]
    SessionNotStarted(String),

    /// Produced when [`ConsumerHandle::stop_and_join`](super::ConsumerHandle::stop_and_join)
    /// detects that [`TraceRouter::on_event`](super::TraceRouter::on_event) panicked inside the
    /// `ProcessTrace` FFI callback and was caught by `std::panic::catch_unwind`, or that the
    /// consumer worker thread itself panicked.
    #[error("ETW consumer callback panicked during execution")]
    CallbackPanicked,

    /// Produced when a Win32 ETW API (`StartTraceW`, `ControlTraceW`, `OpenTraceW`,
    /// `ProcessTrace`, `EnableTraceEx2`, or `TraceSetInformation`) returns a non-zero
    /// Win32 error code.
    #[error("Windows ETW API Error {code}: {message}")]
    WindowsApi {
        /// Raw Win32 error code (e.g., `ERROR_ACCESS_DENIED = 5`, `ERROR_BAD_LENGTH = 24`).
        code: u32,
        /// Human-readable description resolved via `FormatMessageW`.
        message: String,
    },
}

impl EtwError {
    /// Converts a raw Win32 status code into a structured [`EtwError::WindowsApi`] by querying
    /// the OS message table via `FormatMessageW`.
    ///
    /// # Arguments
    ///
    /// * `code` - The Win32 error code returned by an ETW API or `GetLastError()`.
    ///
    /// # Returns
    ///
    /// An [`EtwError::WindowsApi`] containing both the numeric code and its formatted message.
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
