use crate::error::AppError;
use crate::pipeline::Event;
use std::sync::atomic::AtomicBool;
use std::sync::mpsc::SyncSender;
use std::thread::JoinHandle;

/// A common trait defining how to build ETW session properties.
/// This ensures both `UserSessionBuilder` and `KernelSessionBuilder` expose
/// a unified API for configuring underlying buffer parameters.
pub trait EtwSessionBuilder {
    fn set_buffer_size(&mut self, size: u32) -> &mut Self;
    fn set_min_buffers(&mut self, count: u32) -> &mut Self;
    fn set_max_buffers(&mut self, count: u32) -> &mut Self;
    fn set_maximum_file_size(&mut self, size_mb: u32) -> &mut Self;
    fn set_log_file_mode(&mut self, mode: u32) -> &mut Self;
    fn set_flush_timer(&mut self, seconds: u32) -> &mut Self;
    fn set_log_file_name(&mut self, name: String) -> &mut Self;
}

/// Defines the lifecycle and consumption interface for any ETW session.
///
/// Implementors of this trait are responsible for starting the trace,
/// routing the underlying OS events into the unified `Event` pipeline,
/// and cleanly stopping the trace upon shutdown.
pub trait EtwSession {
    fn start(&mut self) -> Result<(), AppError>;
    fn stop(&mut self) -> Result<(), AppError>;
    fn consume(
        &self,
        sender: SyncSender<Event>,
    ) -> Result<JoinHandle<Result<(), AppError>>, AppError>;
}

/// These properties control the buffering and logging behavior of the ETW session.
/// See docs about this stucture at: https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_properties
#[derive(Debug, Clone, Default)]
pub struct EventTraceProperties {
    /// Amount of memory allocated for each event tracing session buffer, in kilobytes.
    pub buffer_size: u32,
    /// Minimum number of buffers allocated for the event tracing session's buffer pool.
    pub minimum_buffers: u32,
    /// Maximum number of buffers allocated for the event tracing session's buffer pool.
    pub maximum_buffers: u32,
    /// Maximum size of the log file, in megabytes.
    pub maximum_file_size: u32,
    /// Logging modes for the session (e.g., EVENT_TRACE_REAL_TIME_MODE, EVENT_TRACE_FILE_MODE_SEQUENTIAL).
    /// For info about the constants values see: https://learn.microsoft.com/en-us/windows/win32/etw/logging-mode-constants
    pub log_file_mode: u32,
    /// How often, in seconds, the trace buffers are forcefully flushed.
    pub flush_timer: u32,
    /// The name of the log file to write to, if writing to disk.
    pub log_file_name: Option<String>,
}

/// Context passed to the ETW C-callback.
/// Windows will pass a pointer to this struct back to us on every event.
pub struct TraceContext {
    pub sender: std::sync::mpsc::SyncSender<Event>,
    pub current_pid: u32,
    pub channel_full_warned: AtomicBool,
}

impl TraceContext {
    /// Creates a new context, caching the current process ID.
    pub fn new(sender: std::sync::mpsc::SyncSender<Event>) -> Self {
        Self {
            sender,
            // Cache the PID once during initialization
            current_pid: std::process::id(),
            // Flag to ensure we only log the full channel warning once
            channel_full_warned: AtomicBool::new(false),
        }
    }
}
