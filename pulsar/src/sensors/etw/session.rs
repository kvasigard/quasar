//! Common traits, configurations, and Win32 lifecycle controllers for ETW sessions.

use std::sync::mpsc::SyncSender;
use std::thread::JoinHandle;

use windows_sys::Win32::Foundation::{ERROR_ALREADY_EXISTS, ERROR_SUCCESS};
use windows_sys::Win32::System::Diagnostics::Etw::{
    CONTROLTRACE_HANDLE, ControlTraceW, EVENT_TRACE_CONTROL_FLUSH, EVENT_TRACE_CONTROL_QUERY,
    EVENT_TRACE_CONTROL_STOP, StartTraceW,
};
use windows_sys::core::GUID;

use super::consumer::{ConsumerHandle, spawn_trace_consumer};
use super::error::EtwError;
use super::event::EventRecord;
use super::masks::PerfGroupMask;
use super::properties::{TracePropertiesBuffer, TraceStatistics};
use super::router::TraceRouter;

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
    fn start(&mut self) -> Result<(), EtwError>;

    /// Stops and closes the ETW trace session.
    fn stop(&mut self) -> Result<(), EtwError>;

    /// Spawns a background thread consuming event records via `ProcessTrace` into a raw `EventRecord` channel.
    fn consume(
        &self,
        sender: SyncSender<EventRecord>,
    ) -> Result<JoinHandle<Result<(), EtwError>>, EtwError> {
        Ok(self.consume_with_router(sender)?.into_join_handle())
    }

    /// Spawns a background thread consuming zero-copy [`RawEvent`](super::raw_event::RawEvent) records
    /// through a custom [`TraceRouter`], returning a [`ConsumerHandle`] with stop-before-close control and metrics.
    fn consume_with_router<R: TraceRouter>(&self, router: R) -> Result<ConsumerHandle, EtwError>;
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

/// Shared low-level Win32 helper that starts a trace session (using V2 properties when `use_v2` is true),
/// automatically taking over orphaned sessions if `ERROR_ALREADY_EXISTS` is returned.
pub(crate) fn start_win32_trace_session(
    session_name: &str,
    properties: &EventTraceProperties,
    session_guid: GUID,
    group_mask: Option<&PerfGroupMask>,
    use_v2: bool,
) -> Result<CONTROLTRACE_HANDLE, EtwError> {
    let name_wide: Vec<u16> = session_name.encode_utf16().chain(Some(0)).collect();
    let enable_flags = group_mask.map_or(0, |m| m.legacy_enable_flags());

    let mut props_buf = if use_v2 {
        TracePropertiesBuffer::new_v2(session_name, properties, session_guid, group_mask)
    } else {
        TracePropertiesBuffer::new(session_name, properties, session_guid, enable_flags)
    };

    let mut handle = CONTROLTRACE_HANDLE { Value: 0 };
    let mut status =
        unsafe { StartTraceW(&mut handle, name_wide.as_ptr(), props_buf.as_mut_ptr()) };

    if status == ERROR_ALREADY_EXISTS {
        log::warn!(
            target: "etw_session",
            "ETW trace session '{}' already exists. Stopping stale session and recreating...",
            session_name
        );

        let mut stop_buf =
            TracePropertiesBuffer::new(session_name, properties, session_guid, 0);

        unsafe {
            ControlTraceW(
                CONTROLTRACE_HANDLE { Value: 0 },
                name_wide.as_ptr(),
                stop_buf.as_mut_ptr(),
                EVENT_TRACE_CONTROL_STOP,
            );

            // Re-initialize props_buf before retrying StartTraceW
            props_buf = if use_v2 {
                TracePropertiesBuffer::new_v2(session_name, properties, session_guid, group_mask)
            } else {
                TracePropertiesBuffer::new(session_name, properties, session_guid, enable_flags)
            };

            status = StartTraceW(&mut handle, name_wide.as_ptr(), props_buf.as_mut_ptr());
        }
    }

    if status == ERROR_SUCCESS {
        Ok(handle)
    } else {
        Err(EtwError::from_win32_code(status))
    }
}

/// Shared low-level Win32 helper that stops an active trace session and returns its final [`TraceStatistics`].
pub(crate) fn stop_win32_trace_session(
    handle: CONTROLTRACE_HANDLE,
    session_name: &str,
    properties: &EventTraceProperties,
    session_guid: GUID,
) -> Result<TraceStatistics, EtwError> {
    let name_wide: Vec<u16> = session_name.encode_utf16().chain(Some(0)).collect();
    let mut props_buf = TracePropertiesBuffer::new(session_name, properties, session_guid, 0);

    let status = unsafe {
        ControlTraceW(
            handle,
            name_wide.as_ptr(),
            props_buf.as_mut_ptr(),
            EVENT_TRACE_CONTROL_STOP,
        )
    };

    if status != ERROR_SUCCESS {
        return Err(EtwError::from_win32_code(status));
    }

    let stats = props_buf.statistics();
    if stats.has_drops() {
        log::warn!(
            target: "etw_session",
            "Session '{}' stopped with kernel telemetry drops: events_lost={}, realtime_buffers_lost={}, log_buffers_lost={}",
            session_name,
            stats.events_lost,
            stats.real_time_buffers_lost,
            stats.log_buffers_lost
        );
    }

    Ok(stats)
}

/// Queries live [`TraceStatistics`] from an active trace session without stopping it.
pub(crate) fn query_win32_trace_session(
    handle: CONTROLTRACE_HANDLE,
    session_name: &str,
    properties: &EventTraceProperties,
    session_guid: GUID,
) -> Result<TraceStatistics, EtwError> {
    let name_wide: Vec<u16> = session_name.encode_utf16().chain(Some(0)).collect();
    let mut props_buf = TracePropertiesBuffer::new(session_name, properties, session_guid, 0);

    let status = unsafe {
        ControlTraceW(
            handle,
            name_wide.as_ptr(),
            props_buf.as_mut_ptr(),
            EVENT_TRACE_CONTROL_QUERY,
        )
    };

    if status != ERROR_SUCCESS {
        return Err(EtwError::from_win32_code(status));
    }

    Ok(props_buf.statistics())
}

/// Forces an immediate buffer flush on an active trace session.
pub(crate) fn flush_win32_trace_session(
    handle: CONTROLTRACE_HANDLE,
    session_name: &str,
    properties: &EventTraceProperties,
    session_guid: GUID,
) -> Result<TraceStatistics, EtwError> {
    let name_wide: Vec<u16> = session_name.encode_utf16().chain(Some(0)).collect();
    let mut props_buf = TracePropertiesBuffer::new(session_name, properties, session_guid, 0);

    let status = unsafe {
        ControlTraceW(
            handle,
            name_wide.as_ptr(),
            props_buf.as_mut_ptr(),
            EVENT_TRACE_CONTROL_FLUSH,
        )
    };

    if status != ERROR_SUCCESS {
        return Err(EtwError::from_win32_code(status));
    }

    Ok(props_buf.statistics())
}

/// Spawns a consumer worker for a started session.
#[inline]
pub(crate) fn spawn_session_consumer<R: TraceRouter>(
    is_started: bool,
    session_name: &str,
    router: R,
) -> Result<ConsumerHandle, EtwError> {
    if !is_started {
        return Err(EtwError::SessionNotStarted(session_name.to_string()));
    }
    spawn_trace_consumer(session_name.to_string(), router)
}
