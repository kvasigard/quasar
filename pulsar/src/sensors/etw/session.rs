//! Common traits, buffer configurations, and shared Win32 lifecycle controllers for ETW sessions.
//!
//! # Unified Session Lifecycle
//!
//! Both kernel-mode ([`KernelSession`](super::KernelSession)) and user-mode
//! ([`UserSession`](super::UserSession)) ETW sessions share the same underlying Win32 control
//! primitives (`StartTraceW`, `ControlTraceW` with `STOP`/`QUERY`/`FLUSH`, and `OpenTraceW`
//! consumer spawning).
//!
//! This module centralizes that Win32 control logic behind crate-internal helpers
//! (`start_win32_trace_session`, `stop_win32_trace_session`, `query_win32_trace_session`, and
//! `flush_win32_trace_session`) while exposing the public [`EtwSessionBuilder`] and [`EtwSession`]
//! traits for polymorphic orchestration in [`SessionDirector`](super::director::SessionDirector).

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

/// Polymorphic builder contract for configuring ETW session ring-buffer and logging properties.
///
/// # Behavioral Contract
///
/// Implementors ([`KernelSessionBuilder`](super::KernelSessionBuilder) and
/// [`UserSessionBuilder`](super::UserSessionBuilder)) store an [`EventTraceProperties`]
/// configuration block that is later materialized into a [`TracePropertiesBuffer`] when
/// [`EtwSession::start`] is called. This trait enables [`SessionDirector::configure_base_session`](super::director::SessionDirector::configure_base_session)
/// to apply uniform EDR buffer sizing and real-time flags across both kernel and user sessions.
///
/// # Examples
///
/// ```
/// use pulsar::sensors::etw::{EtwSessionBuilder, UserSessionBuilder};
///
/// fn apply_edr_buffering(builder: &mut impl EtwSessionBuilder) {
///     builder
///         .set_buffer_size(1024)
///         .set_min_buffers(64)
///         .set_max_buffers(128)
///         .set_flush_timer(1);
/// }
///
/// let mut user_builder = UserSessionBuilder::new("Pulsar-Custom-Session");
/// apply_edr_buffering(&mut user_builder);
/// ```
pub trait EtwSessionBuilder {
    /// Sets the memory allocation size for each individual ring buffer in kilobytes (`BufferSize`).
    fn set_buffer_size(&mut self, size: u32) -> &mut Self;
    /// Sets the minimum number of ring buffers pre-allocated in the session pool (`MinimumBuffers`).
    fn set_min_buffers(&mut self, count: u32) -> &mut Self;
    /// Sets the maximum number of ring buffers allowed in the session pool (`MaximumBuffers`).
    fn set_max_buffers(&mut self, count: u32) -> &mut Self;
    /// Sets the maximum `.etl` log file size in megabytes for file-backed sessions (`MaximumFileSize`).
    #[allow(dead_code)]
    fn set_maximum_file_size(&mut self, size_mb: u32) -> &mut Self;
    /// Sets the `LogFileMode` bitmask (e.g., `EVENT_TRACE_REAL_TIME_MODE`).
    fn set_log_file_mode(&mut self, mode: u32) -> &mut Self;
    /// Sets the forced buffer flush interval in seconds (`FlushTimer`).
    fn set_flush_timer(&mut self, seconds: u32) -> &mut Self;
    /// Sets the output file path for file-backed `.etl` sessions.
    #[allow(dead_code)]
    fn set_log_file_name(&mut self, name: String) -> &mut Self;
}

/// Lifecycle and consumption contract for an active ETW trace session.
///
/// # Behavioral Contract & Ordering Invariants
///
/// 1. **Start Before Consume:** [`EtwSession::start`] must succeed before calling
///    [`EtwSession::consume_with_router`] or [`EtwSession::consume`]; otherwise
///    [`EtwError::SessionNotStarted`] is returned.
/// 2. **Teardown Order:** During graceful shutdown, callers should invoke [`EtwSession::stop`]
///    to halt kernel buffer emission (`ControlTraceW(..., EVENT_TRACE_CONTROL_STOP)`) and then
///    call [`ConsumerHandle::stop_and_join`] to close the consumer handle and join the worker
///    thread. All implementors also invoke `let _ = self.stop();` inside `Drop` as an RAII
///    safety net so trace sessions are never leaked in the OS if a scope exits early.
///
/// # Examples
///
/// ```no_run
/// use pulsar::sensors::etw::{ConsumerOutcome, EtwSession, KernelSessionBuilder, RawEvent};
///
/// let mut session = KernelSessionBuilder::new().build()?;
/// session.start()?;
///
/// let consumer = session.consume_with_router(|_event: &RawEvent, _pid: u32| {
///     ConsumerOutcome::FilteredOut
/// })?;
///
/// session.stop()?;
/// consumer.stop_and_join()?;
/// # Ok::<(), pulsar::sensors::etw::EtwError>(())
/// ```
pub trait EtwSession {
    /// Registers and starts the ETW trace session with the Windows kernel (`StartTraceW`).
    ///
    /// If a stale session with the same name is left over from a previous crashed process
    /// (`ERROR_ALREADY_EXISTS`), the implementation automatically stops the stale session
    /// and retries `StartTraceW`.
    ///
    /// # Errors
    ///
    /// * [`EtwError::SessionAlreadyRunning`] if `start` has already been called on this instance.
    /// * [`EtwError::WindowsApi`] if `StartTraceW` fails (e.g., `ERROR_ACCESS_DENIED` when running
    ///   without Administrator / `SeSystemProfilePrivilege` privileges).
    fn start(&mut self) -> Result<(), EtwError>;

    /// Stops and unregisters the active ETW trace session in the Windows kernel (`ControlTraceW`).
    ///
    /// Idempotent: calling `stop` on an unstarted or already-stopped session returns `Ok(())`.
    ///
    /// # Errors
    ///
    /// * [`EtwError::WindowsApi`] if `ControlTraceW(..., EVENT_TRACE_CONTROL_STOP)` fails.
    fn stop(&mut self) -> Result<(), EtwError>;

    /// Spawns a background worker thread consuming events via `ProcessTrace` into a bounded
    /// channel of owned [`EventRecord`] instances.
    ///
    /// Prefer [`Self::consume_with_router`] in high-throughput production pipelines to avoid
    /// per-event `Vec<u8>` payload allocations.
    ///
    /// # Errors
    ///
    /// * [`EtwError::SessionNotStarted`] if [`Self::start`] has not been called.
    fn consume(
        &self,
        sender: SyncSender<EventRecord>,
    ) -> Result<JoinHandle<Result<(), EtwError>>, EtwError> {
        Ok(self.consume_with_router(sender)?.into_join_handle())
    }

    /// Spawns a background worker thread consuming zero-copy [`RawEvent`](super::raw_event::RawEvent)
    /// borrows through `router`, returning a [`ConsumerHandle`] with deterministic `CloseTrace`
    /// control and batch-updated [`ConsumerMetrics`](super::ConsumerMetrics).
    ///
    /// # Errors
    ///
    /// * [`EtwError::SessionNotStarted`] if [`Self::start`] has not been called.
    fn consume_with_router<R: TraceRouter>(&self, router: R) -> Result<ConsumerHandle, EtwError>;
}

/// Configuration values controlling the kernel ring-buffer pool and flushing behavior of an ETW session.
///
/// Materialized into an aligned Win32 `EVENT_TRACE_PROPERTIES` or `EVENT_TRACE_PROPERTIES_V2`
/// block by [`TracePropertiesBuffer`].
///
/// Reference: <https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_properties>
#[derive(Debug, Clone, Default)]
pub struct EventTraceProperties {
    /// Size of each individual ETW ring buffer in kilobytes (`BufferSize`).
    pub buffer_size: u32,
    /// Minimum number of buffers pre-allocated in the non-paged/system memory pool (`MinimumBuffers`).
    pub minimum_buffers: u32,
    /// Maximum number of buffers the kernel may allocate under heavy load (`MaximumBuffers`).
    pub maximum_buffers: u32,
    /// Maximum size of the output `.etl` file in megabytes (`MaximumFileSize`, `0` for real-time sessions).
    #[allow(dead_code)]
    pub maximum_file_size: u32,
    /// Bitmask of `EVENT_TRACE_*_MODE` flags (e.g., `EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_SYSTEM_LOGGER_MODE`).
    pub log_file_mode: u32,
    /// Interval in seconds at which partially filled buffers are forcefully flushed (`FlushTimer`).
    pub flush_timer: u32,
    /// Optional `.etl` file path when writing trace output to disk.
    pub log_file_name: Option<String>,
}

/// Starts a Win32 ETW trace session via `StartTraceW`, using [`TracePropertiesBuffer::new_v2`]
/// when `use_v2` is true, and automatically reclaiming orphaned sessions on `ERROR_ALREADY_EXISTS`.
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
    // SAFETY: `name_wide` is a null-terminated UTF-16 string and `props_buf` is an 8-byte-aligned
    // `EVENT_TRACE_PROPERTIES[_V2]` buffer with `Wnode.BufferSize` matching its allocation.
    let mut status =
        unsafe { StartTraceW(&mut handle, name_wide.as_ptr(), props_buf.as_mut_ptr()) };

    // If a previous agent process terminated abruptly (e.g. SIGKILL / power loss) without
    // running `Drop`, the kernel session remains active under `session_name`. Stop it by name
    // (`handle = 0`) and immediately re-create it with fresh buffer properties.
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

            // Re-initialize `props_buf` before retrying `StartTraceW` because the failed first
            // call may have mutated header fields inside `props_buf`.
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

/// Stops an active Win32 trace session via `ControlTraceW(..., EVENT_TRACE_CONTROL_STOP)`
/// and extracts the final kernel [`TraceStatistics`] (logging a warning if kernel drops occurred).
pub(crate) fn stop_win32_trace_session(
    handle: CONTROLTRACE_HANDLE,
    session_name: &str,
    properties: &EventTraceProperties,
    session_guid: GUID,
) -> Result<TraceStatistics, EtwError> {
    let name_wide: Vec<u16> = session_name.encode_utf16().chain(Some(0)).collect();
    let mut props_buf = TracePropertiesBuffer::new(session_name, properties, session_guid, 0);

    // SAFETY: `handle` is an active session handle and `props_buf` is a valid properties buffer.
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

/// Queries live [`TraceStatistics`] from an active trace session via `ControlTraceW(..., EVENT_TRACE_CONTROL_QUERY)`.
pub(crate) fn query_win32_trace_session(
    handle: CONTROLTRACE_HANDLE,
    session_name: &str,
    properties: &EventTraceProperties,
    session_guid: GUID,
) -> Result<TraceStatistics, EtwError> {
    let name_wide: Vec<u16> = session_name.encode_utf16().chain(Some(0)).collect();
    let mut props_buf = TracePropertiesBuffer::new(session_name, properties, session_guid, 0);

    // SAFETY: `handle` is an active session handle and `props_buf` is a valid properties buffer.
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

/// Forces an immediate kernel buffer flush on an active session via `ControlTraceW(..., EVENT_TRACE_CONTROL_FLUSH)`.
pub(crate) fn flush_win32_trace_session(
    handle: CONTROLTRACE_HANDLE,
    session_name: &str,
    properties: &EventTraceProperties,
    session_guid: GUID,
) -> Result<TraceStatistics, EtwError> {
    let name_wide: Vec<u16> = session_name.encode_utf16().chain(Some(0)).collect();
    let mut props_buf = TracePropertiesBuffer::new(session_name, properties, session_guid, 0);

    // SAFETY: `handle` is an active session handle and `props_buf` is a valid properties buffer.
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

/// Validates that a session has been started before delegating to [`spawn_trace_consumer`].
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
