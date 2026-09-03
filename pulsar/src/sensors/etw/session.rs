//! Common traits and configurations defining the ETW session contract.

use std::sync::mpsc::SyncSender;
use std::thread::JoinHandle;

use super::error::EtwError;
use crate::sensors::etw::EventRecord;

/// A common trait defining how to build ETW session properties.
///
/// Ensures both user-mode and kernel-mode session builders expose
/// a unified API for configuring underlying buffer parameters.
pub trait EtwSessionBuilder {
    /// Sets the buffer allocation size in kilobytes.
    fn set_buffer_size(&mut self, size: u32) -> &mut Self;
    /// Sets the minimum number of buffers in the pool.
    fn set_min_buffers(&mut self, count: u32) -> &mut Self;
    /// Sets the maximum number of buffers in the pool.
    fn set_max_buffers(&mut self, count: u32) -> &mut Self;
    /// Sets the maximum log file size in megabytes (for file-backed sessions).
    #[allow(dead_code)]
    fn set_maximum_file_size(&mut self, size_mb: u32) -> &mut Self;
    /// Sets the logging mode bitmask (e.g. `EVENT_TRACE_REAL_TIME_MODE`).
    fn set_log_file_mode(&mut self, mode: u32) -> &mut Self;
    /// Sets the forced buffer flush interval in seconds.
    fn set_flush_timer(&mut self, seconds: u32) -> &mut Self;
    /// Sets the log file name for file-backed sessions.
    #[allow(dead_code)]
    fn set_log_file_name(&mut self, name: String) -> &mut Self;
}

/// Defines the lifecycle and consumption interface for an active ETW session.
///
/// Implementors are responsible for starting the trace session,
/// routing OS event records into the pipeline channel, and stopping the trace.
pub trait EtwSession {
    /// Starts the ETW trace session with Windows.
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, or `Err(EtwError)` if session creation fails.
    ///
    /// # Errors
    ///
    /// Returns [`EtwError::WindowsApi`] if `StartTraceW` or `ControlTraceW` fails.
    fn start(&mut self) -> Result<(), EtwError>;

    /// Stops and closes the ETW trace session.
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, or `Err(EtwError)` on failure.
    ///
    /// # Errors
    ///
    /// Returns [`EtwError::WindowsApi`] if `ControlTraceW` fails.
    fn stop(&mut self) -> Result<(), EtwError>;

    /// Spawns a background thread consuming event records via `ProcessTrace`.
    ///
    /// # Arguments
    ///
    /// * `sender` - Synchronous channel sender pushing raw `EventRecord` items to the dispatcher.
    ///
    /// # Returns
    ///
    /// A `JoinHandle` for the consumer thread.
    ///
    /// # Errors
    ///
    /// Returns [`EtwError::WindowsApi`] if `OpenTraceW` fails, or [`EtwError::SessionNotStarted`].
    fn consume(
        &self,
        sender: SyncSender<EventRecord>,
    ) -> Result<JoinHandle<Result<(), EtwError>>, EtwError>;
}

/// Properties controlling the buffering and logging behavior of the ETW session.
///
/// Reference: <https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_properties>
#[derive(Debug, Clone, Default)]
pub struct EventTraceProperties {
    /// Amount of memory allocated for each event tracing session buffer, in kilobytes.
    pub buffer_size: u32,
    /// Minimum number of buffers allocated for the event tracing session's buffer pool.
    pub minimum_buffers: u32,
    /// Maximum number of buffers allocated for the event tracing session's buffer pool.
    pub maximum_buffers: u32,
    /// Maximum size of the log file, in megabytes.
    #[allow(dead_code)]
    pub maximum_file_size: u32,
    /// Logging modes for the session (e.g. `EVENT_TRACE_REAL_TIME_MODE`).
    pub log_file_mode: u32,
    /// How often, in seconds, the trace buffers are forcefully flushed.
    pub flush_timer: u32,
    /// The name of the log file to write to, if writing to disk.
    pub log_file_name: Option<String>,
}
