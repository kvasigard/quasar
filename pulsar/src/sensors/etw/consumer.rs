//! Background ETW trace consumer worker, FFI-safe callbacks, and lifecycle handle.
//!
//! This module manages the `OpenTraceW` / `ProcessTrace` / `CloseTrace` loop on a dedicated
//! background thread. It contains zero dependencies on upper-layer pipeline constants or schemas:
//! all filtering and zero-copy decoding are delegated through [`TraceRouter`].

use std::ffi::c_void;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread::JoinHandle;

use windows_sys::Win32::Foundation::{ERROR_CANCELLED, ERROR_SUCCESS, GetLastError};
use windows_sys::Win32::System::Diagnostics::Etw::{
    CloseTrace, EVENT_RECORD, EVENT_TRACE_LOGFILEW, OpenTraceW, PROCESS_TRACE_MODE_EVENT_RECORD,
    PROCESS_TRACE_MODE_RAW_TIMESTAMP, PROCESS_TRACE_MODE_REAL_TIME, PROCESSTRACE_HANDLE,
    ProcessTrace,
};

use super::error::EtwError;
use super::raw_event::RawEvent;
use super::router::{ConsumerMetrics, ConsumerMetricsSnapshot, ConsumerOutcome, TraceRouter};

const INVALID_TRACE_HANDLE: u64 = u64::MAX;

/// Control handle for an active background `ProcessTrace` consumer thread.
///
/// Allows the owning session to signal cancellation, deterministically unblock `ProcessTrace`
/// via `CloseTrace`, query real-time [`ConsumerMetrics`], and join the worker thread.
pub struct ConsumerHandle {
    stop_flag: Arc<AtomicBool>,
    trace_handle_raw: Arc<AtomicU64>,
    metrics: Arc<ConsumerMetrics>,
    join_handle: Option<JoinHandle<Result<(), EtwError>>>,
}

impl ConsumerHandle {
    /// Signals the consumer to stop at the next event/buffer boundary and closes the
    /// active `PROCESSTRACE_HANDLE` so `ProcessTrace` unblocks immediately.
    pub fn request_stop(&self) {
        self.stop_flag.store(true, Ordering::Release);
        let handle_val = self
            .trace_handle_raw
            .swap(INVALID_TRACE_HANDLE, Ordering::AcqRel);
        if handle_val != INVALID_TRACE_HANDLE && handle_val != 0 {
            // SAFETY: `handle_val` was obtained from `OpenTraceW` and atomic `swap` guarantees
            // `CloseTrace` is invoked at most once across `request_stop` and consumer exit.
            unsafe {
                CloseTrace(PROCESSTRACE_HANDLE { Value: handle_val });
            }
        }
    }

    /// Returns a shared reference to the consumer's batch-updated atomic telemetry metrics.
    #[inline]
    pub fn metrics(&self) -> &Arc<ConsumerMetrics> {
        &self.metrics
    }

    /// Reads a point-in-time snapshot of the consumer's telemetry counters.
    #[inline]
    pub fn metrics_snapshot(&self) -> ConsumerMetricsSnapshot {
        self.metrics.snapshot()
    }

    /// Signals stop, waits for the consumer thread to finish, and returns its final result.
    pub fn stop_and_join(mut self) -> Result<(), EtwError> {
        self.request_stop();
        if let Some(handle) = self.join_handle.take() {
            match handle.join() {
                Ok(res) => res,
                Err(_) => Err(EtwError::CallbackPanicked),
            }
        } else {
            Ok(())
        }
    }

    /// Consumes this handle and returns the underlying thread `JoinHandle`.
    #[inline]
    pub fn into_join_handle(mut self) -> JoinHandle<Result<(), EtwError>> {
        self.join_handle
            .take()
            .expect("ConsumerHandle join_handle already taken")
    }
}

/// Context pinned on the consumer worker thread stack for the duration of `ProcessTrace`.
pub struct TraceContext<R: TraceRouter> {
    router: R,
    current_pid: u32,
    stop_flag: Arc<AtomicBool>,
    poisoned: bool,
    channel_full_warned: bool,
    local_metrics: ConsumerMetricsSnapshot,
    shared_metrics: Arc<ConsumerMetrics>,
}

impl<R: TraceRouter> TraceContext<R> {
    /// Creates a new `TraceContext` wrapping the given [`TraceRouter`].
    pub fn new(
        router: R,
        stop_flag: Arc<AtomicBool>,
        shared_metrics: Arc<ConsumerMetrics>,
    ) -> Self {
        Self {
            router,
            current_pid: std::process::id(),
            stop_flag,
            poisoned: false,
            channel_full_warned: false,
            local_metrics: ConsumerMetricsSnapshot::default(),
            shared_metrics,
        }
    }

    /// Processes a single `&RawEvent` with panic containment and local metric accounting.
    #[inline]
    pub fn process_raw_event(&mut self, raw_event: &RawEvent) {
        if self.poisoned || self.stop_flag.load(Ordering::Relaxed) {
            return;
        }

        self.local_metrics.events_received += 1;
        let current_pid = self.current_pid;
        let router = &self.router;

        let result = catch_unwind(AssertUnwindSafe(|| router.on_event(raw_event, current_pid)));

        match result {
            Ok(ConsumerOutcome::FilteredOut) => {
                self.local_metrics.events_filtered_out += 1;
            }
            Ok(ConsumerOutcome::Dispatched) => {
                self.local_metrics.events_dispatched += 1;
            }
            Ok(ConsumerOutcome::DroppedChannelFull) => {
                self.local_metrics.events_dropped_channel_full += 1;
                if !self.channel_full_warned {
                    self.channel_full_warned = true;
                    log::warn!(
                        target: "etw_consumer",
                        "An ETW pipeline channel reached maximum capacity; dropping excess events."
                    );
                }
            }
            Ok(ConsumerOutcome::ParseError) => {
                self.local_metrics.parse_errors += 1;
            }
            Ok(ConsumerOutcome::ChannelDisconnected) => {
                self.stop_flag.store(true, Ordering::Release);
            }
            Err(_) => {
                self.poisoned = true;
                self.stop_flag.store(true, Ordering::Release);
                log::error!(
                    target: "etw_consumer",
                    "Panic caught at FFI boundary inside ETW event callback; terminating trace consumer."
                );
            }
        }
    }

    /// Flushes thread-local counters into the shared atomic [`ConsumerMetrics`].
    #[inline]
    pub fn flush_metrics(&mut self) {
        self.shared_metrics.record_batch(&mut self.local_metrics);
    }
}

/// Static C-ABI `EventRecordCallback` invoked synchronously by Windows via `ProcessTrace`.
///
/// # Safety
///
/// `record` must be a valid pointer to an `EVENT_RECORD` whose `UserContext` points to `TraceContext<R>`.
unsafe extern "system" fn etw_event_callback<R: TraceRouter>(record: *mut EVENT_RECORD) {
    let Some(raw_event) = (unsafe { RawEvent::from_ptr(record) }) else {
        return;
    };

    let ctx_ptr = raw_event.as_raw().UserContext as *mut TraceContext<R>;
    if ctx_ptr.is_null() {
        return;
    }

    // SAFETY: `ctx_ptr` points to the `TraceContext<R>` pinned on the `ProcessTrace` stack frame.
    let ctx = unsafe { &mut *ctx_ptr };
    ctx.process_raw_event(raw_event);
}

/// Static C-ABI `BufferCallback` invoked by Windows after each ETW buffer is delivered.
///
/// Flushes per-buffer telemetry counters and returns `0` (`FALSE`) to cleanly terminate
/// `ProcessTrace` if a stop or panic has occurred.
unsafe extern "system" fn etw_buffer_callback<R: TraceRouter>(
    logfile: *mut EVENT_TRACE_LOGFILEW,
) -> u32 {
    if logfile.is_null() {
        return 0;
    }

    // SAFETY: `logfile` is provided by `ProcessTrace` and its `Context` points to `TraceContext<R>`.
    let ctx_ptr = unsafe { (*logfile).Context as *mut TraceContext<R> };
    if ctx_ptr.is_null() {
        return 0;
    }

    let ctx = unsafe { &mut *ctx_ptr };
    ctx.local_metrics.buffers_processed += 1;
    ctx.flush_metrics();

    if ctx.poisoned || ctx.stop_flag.load(Ordering::Relaxed) {
        0 // FALSE -> instructs ProcessTrace to stop processing and return
    } else {
        1 // TRUE -> continue processing buffers
    }
}

/// Spawns a dedicated background thread consuming events from an active ETW session via `ProcessTrace`.
///
/// # Arguments
///
/// * `session_name` - The name of the started ETW session.
/// * `router` - Implementation of [`TraceRouter`] that filters, decodes, and routes events.
///
/// # Returns
///
/// A [`ConsumerHandle`] managing the background consumer lifecycle and metrics.
pub fn spawn_trace_consumer<R: TraceRouter>(
    session_name: String,
    router: R,
) -> Result<ConsumerHandle, EtwError> {
    log::info!(
        target: "etw_consumer",
        "Spawning background ETW consumer thread for session '{}'...",
        session_name
    );

    let stop_flag = Arc::new(AtomicBool::new(false));
    let trace_handle_raw = Arc::new(AtomicU64::new(INVALID_TRACE_HANDLE));
    let metrics = Arc::new(ConsumerMetrics::new());

    let thread_stop = Arc::clone(&stop_flag);
    let thread_handle_raw = Arc::clone(&trace_handle_raw);
    let thread_metrics = Arc::clone(&metrics);
    let thread_name = format!("pulsar-etw-{}", session_name.to_lowercase());

    let join_handle = std::thread::Builder::new()
        .name(thread_name)
        .spawn(move || {
            let mut name_wide: Vec<u16> = session_name.encode_utf16().chain(Some(0)).collect();
            let mut context = TraceContext::new(router, thread_stop, thread_metrics);
            let mut logfile: EVENT_TRACE_LOGFILEW = unsafe { std::mem::zeroed() };

            logfile.LoggerName = name_wide.as_mut_ptr();
            logfile.Anonymous1.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME
                | PROCESS_TRACE_MODE_EVENT_RECORD
                | PROCESS_TRACE_MODE_RAW_TIMESTAMP;
            logfile.Anonymous2.EventRecordCallback = Some(etw_event_callback::<R>);
            logfile.BufferCallback = Some(etw_buffer_callback::<R>);
            logfile.Context = &mut context as *mut TraceContext<R> as *mut c_void;

            // SAFETY: `logfile` is properly initialized and outlives `OpenTraceW` and `ProcessTrace`.
            let status = unsafe {
                let trace_handle = OpenTraceW(&mut logfile);
                if trace_handle.Value == INVALID_TRACE_HANDLE || trace_handle.Value == 0 {
                    let err_code = GetLastError();
                    return Err(EtwError::from_win32_code(err_code));
                }

                thread_handle_raw.store(trace_handle.Value, Ordering::Release);

                log::debug!(
                    target: "etw_consumer",
                    "Blocking ProcessTrace loop started for session '{}'.",
                    session_name
                );

                let status = ProcessTrace(
                    &trace_handle,
                    1,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                );

                // Ensure the trace handle is closed if `request_stop` has not already closed it.
                let prev = thread_handle_raw.swap(INVALID_TRACE_HANDLE, Ordering::AcqRel);
                if prev != INVALID_TRACE_HANDLE && prev != 0 {
                    CloseTrace(PROCESSTRACE_HANDLE { Value: prev });
                }

                status
            };

            context.flush_metrics();

            if context.poisoned {
                return Err(EtwError::CallbackPanicked);
            }

            if status != ERROR_SUCCESS && status != ERROR_CANCELLED {
                return Err(EtwError::from_win32_code(status));
            }

            log::info!(
                target: "etw_consumer",
                "ETW consumer thread for '{}' exited gracefully.",
                session_name
            );
            Ok(())
        })
        .expect("Failed to spawn pulsar-etw-consumer thread");

    Ok(ConsumerHandle {
        stop_flag,
        trace_handle_raw,
        metrics,
        join_handle: Some(join_handle),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sensors::etw::raw_event::SyntheticEvent;
    use windows_sys::core::GUID;

    const DUMMY_GUID: GUID = GUID {
        data1: 0x1234_5678,
        data2: 0,
        data3: 0,
        data4: [0; 8],
    };

    #[test]
    fn test_trace_context_catches_panic_across_ffi_boundary() {
        let stop_flag = Arc::new(AtomicBool::new(false));
        let metrics = Arc::new(ConsumerMetrics::new());

        let mut ctx = TraceContext::new(
            |_evt: &RawEvent, _pid: u32| -> ConsumerOutcome {
                panic!("simulated bug inside router");
            },
            Arc::clone(&stop_flag),
            Arc::clone(&metrics),
        );

        let syn = SyntheticEvent::new(DUMMY_GUID, 2, 1, 9999, 100, 5000, vec![1, 2, 3]);
        ctx.process_raw_event(&syn);
        ctx.flush_metrics();

        assert!(ctx.poisoned, "Context must mark itself poisoned after panic");
        assert!(
            stop_flag.load(Ordering::Relaxed),
            "Stop flag must be set when callback panics"
        );
        assert_eq!(metrics.snapshot().events_received, 1);
    }

    #[test]
    fn test_trace_context_metrics_accounting() {
        let stop_flag = Arc::new(AtomicBool::new(false));
        let metrics = Arc::new(ConsumerMetrics::new());

        let mut ctx = TraceContext::new(
            |evt: &RawEvent, _pid: u32| -> ConsumerOutcome {
                match evt.opcode() {
                    1 => ConsumerOutcome::Dispatched,
                    2 => ConsumerOutcome::FilteredOut,
                    3 => ConsumerOutcome::DroppedChannelFull,
                    _ => ConsumerOutcome::ParseError,
                }
            },
            Arc::clone(&stop_flag),
            Arc::clone(&metrics),
        );

        for opcode in [1u8, 1, 2, 3, 99] {
            let syn = SyntheticEvent::new(DUMMY_GUID, 2, opcode, 9999, 100, 5000, Vec::new());
            ctx.process_raw_event(&syn);
        }
        ctx.flush_metrics();

        let snap = metrics.snapshot();
        assert_eq!(snap.events_received, 5);
        assert_eq!(snap.events_dispatched, 2);
        assert_eq!(snap.events_filtered_out, 1);
        assert_eq!(snap.events_dropped_channel_full, 1);
        assert_eq!(snap.parse_errors, 1);
    }
}
