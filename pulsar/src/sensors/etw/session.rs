//! Common ETW session traits and configuration properties.

use std::sync::atomic::AtomicBool;
use std::thread::JoinHandle;
use crossbeam_channel::Sender;

use crate::error::AppError;
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
pub trait EtwSession {
    /// Starts the ETW trace session with Windows.
    fn start(&mut self) -> Result<(), AppError>;

    /// Stops and closes the ETW trace session.
    fn stop(&mut self) -> Result<(), AppError>;

    /// Spawns a background thread consuming event records via `ProcessTrace`.
    fn consume(
        &self,
        sender: Sender<EventRecord>,
    ) -> Result<JoinHandle<Result<(), AppError>>, AppError>;
}

/// Properties controlling the buffering and logging behavior of the ETW session.
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

/// Context passed to the ETW C-callback function.
pub struct TraceContext {
    /// Sender channel forwarding raw event records to the ingress pipeline.
    pub sender: Sender<EventRecord>,
    /// Process ID of the tracer to filter out self-generated telemetry.
    pub current_pid: u32,
    /// Flag ensuring the channel saturation warning is only emitted once.
    pub channel_full_warned: AtomicBool,
}

impl TraceContext {
    /// Creates a new `TraceContext`, caching the current process ID.
    pub fn new(sender: Sender<EventRecord>) -> Self {
        Self {
            sender,
            current_pid: std::process::id(),
            channel_full_warned: AtomicBool::new(false),
        }
    }
}
