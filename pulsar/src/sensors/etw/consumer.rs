//! Background ETW trace consumer worker, FFI-safe Win32 callbacks, and lifecycle handle.
//!
//! # Responsibility & Lifecycle
//!
//! This module manages the real-time `OpenTraceW` → `ProcessTrace` → `CloseTrace` lifecycle
//! on a dedicated background worker thread (`pulsar-etw-<session>`).
//!
//! Key architectural guarantees implemented in this module:
//! - **FFI Panic Safety:** Unwinding a Rust panic across the `extern "system"` callback
//!   boundary into `sechost.dll` / `advapi32.dll` is Immediate Undefined Behavior.
//!   [`TraceContext::process_raw_event`] wraps every [`TraceRouter::on_event`] invocation in
//!   `std::panic::catch_unwind`, sets a poison flag on panic, and causes `etw_buffer_callback`
//!   to return `0` (`FALSE`) so `ProcessTrace` unwinds cleanly in C and returns
//!   [`EtwError::CallbackPanicked`].
//! - **Deterministic Teardown (`CloseTrace` + `BufferCallback`):** Because `ProcessTrace` blocks
//!   indefinitely while waiting for real-time buffers, [`ConsumerHandle`] stores the raw
//!   `PROCESSTRACE_HANDLE` in an `AtomicU64`. Calling [`ConsumerHandle::request_stop`] or
//!   [`ConsumerHandle::stop_and_join`] atomically swaps the handle with [`INVALID_TRACE_HANDLE`]
//!   and calls `CloseTrace` at most once, immediately unblocking `ProcessTrace` even when a
//!   session has zero event traffic.
//! - **Pinned Stack Context:** [`TraceContext`] is allocated on the consumer worker thread's
//!   stack frame before `OpenTraceW` and remains pinned in place until `ProcessTrace` returns,
//!   ensuring the raw `UserContext` / `Context` pointer passed to Windows never dangles.

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

/// Sentinel value (`0xFFFF_FFFF_FFFF_FFFF`, i.e. `INVALID_PROCESSTRACE_HANDLE`) indicating
/// that an `OpenTraceW` handle is either not yet opened, failed to open, or has already been
/// closed via `CloseTrace`.
const INVALID_TRACE_HANDLE: u64 = u64::MAX;

/// Control handle for an active background `ProcessTrace` consumer worker thread.
///
/// # Ownership & Concurrency Invariants
///
/// Returned by [`EtwSession::consume_with_router`](super::EtwSession::consume_with_router).
/// Coordinates safe teardown between the session controller thread and the background
/// `ProcessTrace` thread:
/// - `trace_handle_raw` holds the active `PROCESSTRACE_HANDLE.Value` and uses atomic
///   `swap(INVALID_TRACE_HANDLE, Ordering::AcqRel)` so `CloseTrace` is guaranteed to execute
///   at most once whether initiated externally via [`Self::request_stop`] or internally when
///   `ProcessTrace` exits on its own.
pub struct ConsumerHandle {
    /// Shared cancellation flag checked by [`TraceContext`] and `etw_buffer_callback`.
    stop_flag: Arc<AtomicBool>,
    /// Atomic `PROCESSTRACE_HANDLE.Value` (`INVALID_TRACE_HANDLE` when uninitialized or already closed).
    trace_handle_raw: Arc<AtomicU64>,
    /// Batch-updated atomic telemetry counters shared with the consumer thread.
    metrics: Arc<ConsumerMetrics>,
    /// Background thread join handle returning the final consumer status.
    join_handle: Option<JoinHandle<Result<(), EtwError>>>,
}

impl ConsumerHandle {
    /// Signals the consumer to stop at the next event/buffer boundary and closes the
    /// active `PROCESSTRACE_HANDLE` so `ProcessTrace` unblocks immediately.
    ///
    /// Safe and idempotent to call multiple times.
    pub fn request_stop(&self) {
        self.stop_flag.store(true, Ordering::Release);
        // Atomically claim ownership of the handle value so neither a concurrent `request_stop`
        // nor the worker thread's post-`ProcessTrace` cleanup can double-close the handle.
        let handle_val = self
            .trace_handle_raw
            .swap(INVALID_TRACE_HANDLE, Ordering::AcqRel);
        if handle_val != INVALID_TRACE_HANDLE && handle_val != 0 {
            // SAFETY: `handle_val` was returned by a successful `OpenTraceW` call and atomic
            // `swap` guarantees `CloseTrace` is called on it at most once.
            unsafe {
                CloseTrace(PROCESSTRACE_HANDLE { Value: handle_val });
            }
        }
    }

    /// Returns a shared reference to the consumer's batch-updated atomic [`ConsumerMetrics`].
    #[inline]
    pub fn metrics(&self) -> &Arc<ConsumerMetrics> {
        &self.metrics
    }

    /// Reads a point-in-time [`ConsumerMetricsSnapshot`] of the consumer's telemetry counters.
    #[inline]
    pub fn metrics_snapshot(&self) -> ConsumerMetricsSnapshot {
        self.metrics.snapshot()
    }

    /// Signals the consumer to stop, closes its trace handle, waits for the background thread
    /// to finish, and returns its final result.
    ///
    /// # Errors
    ///
    /// * [`EtwError::CallbackPanicked`] if the [`TraceRouter`] panicked inside the callback
    ///   or the worker thread panicked.
    /// * [`EtwError::WindowsApi`] if `OpenTraceW` or `ProcessTrace` failed with a Win32 error
    ///   other than `ERROR_SUCCESS` or `ERROR_CANCELLED`.
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

    /// Consumes this handle and extracts the underlying thread `JoinHandle` without signaling stop.
    ///
    /// # Panics
    ///
    /// Panics if the `JoinHandle` was already consumed (which cannot occur through public APIs
    /// because both `stop_and_join` and `into_join_handle` consume `self` by value).
    #[inline]
    pub fn into_join_handle(mut self) -> JoinHandle<Result<(), EtwError>> {
        self.join_handle
            .take()
            .expect("ConsumerHandle join_handle already taken")
    }
}

/// Per-consumer execution state pinned on the worker thread's stack during `ProcessTrace`.
///
/// # Role & Thread-Safety Invariants
///
/// A pointer to `TraceContext<R>` is stored in `EVENT_TRACE_LOGFILEW.Context` and passed back
/// to `etw_event_callback` (via `EVENT_RECORD.UserContext`) and `etw_buffer_callback`
/// (via `EVENT_TRACE_LOGFILEW.Context`).
///
/// Because Windows invokes both callbacks strictly sequentially on the thread that called
/// `ProcessTrace`, `TraceContext` mutates its `local_metrics`, `poisoned`, and
/// `channel_full_warned` fields without synchronization overhead, and only touches
/// `shared_metrics` once per buffer flush.
pub struct TraceContext<R: TraceRouter> {
    /// Decoupled zero-copy event router implementation.
    router: R,
    /// Cached PID of the current Pulsar agent process (`std::process::id()`).
    current_pid: u32,
    /// Shared cancellation flag signaled by [`ConsumerHandle::request_stop`] or channel disconnection.
    stop_flag: Arc<AtomicBool>,
    /// Set to `true` if `router.on_event` panicked; suppresses subsequent events and aborts the buffer loop.
    poisoned: bool,
    /// Rate-limits backpressure warnings so a full channel logs at most one `WARN` message per session.
    channel_full_warned: bool,
    /// Thread-local counter batch accumulated across events within the current ETW buffer.
    local_metrics: ConsumerMetricsSnapshot,
    /// Shared atomic metrics updated once per buffer inside [`Self::flush_metrics`].
    shared_metrics: Arc<ConsumerMetrics>,
}

impl<R: TraceRouter> TraceContext<R> {
    /// Creates a new [`TraceContext`] wrapping `router` and bound to `stop_flag` and `shared_metrics`.
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

    /// Processes a single borrowed [`RawEvent`] with FFI panic containment and thread-local metric accounting.
    ///
    /// If the context is already poisoned or `stop_flag` has been set, this method returns
    /// immediately without invoking the router so the current buffer drains as fast as possible
    /// until `etw_buffer_callback` terminates `ProcessTrace`.
    #[inline]
    pub fn process_raw_event(&mut self, raw_event: &RawEvent) {
        if self.poisoned || self.stop_flag.load(Ordering::Relaxed) {
            return;
        }

        self.local_metrics.events_received += 1;
        let current_pid = self.current_pid;
        let router = &self.router;

        // Guard the C-ABI callback boundary: a panic escaping `extern "system" fn` into Windows
        // `ProcessTrace` would be immediate Undefined Behavior.
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

/// Static C-ABI `EventRecordCallback` invoked synchronously by Windows for each event in a trace buffer.
///
/// # Safety
///
/// Invoked by the Windows ETW runtime during `ProcessTrace`. If `record` is non-null, it must
/// point to a valid `EVENT_RECORD` whose `UserContext` field holds the `*mut TraceContext<R>`
/// pointer initialized in [`spawn_trace_consumer`].
unsafe extern "system" fn etw_event_callback<R: TraceRouter>(record: *mut EVENT_RECORD) {
    let Some(raw_event) = (unsafe { RawEvent::from_ptr(record) }) else {
        return;
    };

    let ctx_ptr = raw_event.as_raw().UserContext as *mut TraceContext<R>;
    if ctx_ptr.is_null() {
        return;
    }

    // SAFETY: `ctx_ptr` points to the `TraceContext<R>` local variable on the `ProcessTrace`
    // worker thread stack, and `ProcessTrace` invokes callbacks single-threaded on that same thread.
    let ctx = unsafe { &mut *ctx_ptr };
    ctx.process_raw_event(raw_event);
}

/// Static C-ABI `BufferCallback` invoked by Windows after all events in an ETW buffer have been delivered.
///
/// Flushes accumulated thread-local telemetry counters to [`ConsumerMetrics`] and checks
/// whether the consumer has been asked to stop or was poisoned by a callback panic.
///
/// # Returns
///
/// `0` (`FALSE`) to instruct `ProcessTrace` to stop processing and return immediately, or
/// `1` (`TRUE`) to continue draining subsequent buffers.
///
/// # Safety
///
/// Invoked by the Windows ETW runtime during `ProcessTrace`. If `logfile` is non-null, its
/// `Context` field must point to the valid `TraceContext<R>` on the consumer thread's stack.
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

    // Returning FALSE (0) from BufferCallback is the documented Win32 mechanism to cancel
    // ProcessTrace cleanly at a buffer boundary without corrupting internal ETW state.
    if ctx.poisoned || ctx.stop_flag.load(Ordering::Relaxed) {
        0
    } else {
        1
    }
}

/// Spawns a dedicated background thread consuming real-time events from an active ETW session via `ProcessTrace`.
///
/// # Arguments
///
/// * `session_name` - Name of the started ETW session (e.g., `"Pulsar-Kernel-Logger"`).
/// * `router` - [`TraceRouter`] implementation that filters, decodes, and routes `&RawEvent` records.
///
/// # Returns
///
/// A [`ConsumerHandle`] providing stop signaling, `CloseTrace` unblocking, and live [`ConsumerMetrics`].
///
/// # Panics
///
/// Panics only if the OS refuses to spawn a new thread (`std::thread::Builder::spawn`).
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
            // `context` lives on this thread's stack frame and outlives both `OpenTraceW` and `ProcessTrace`.
            let mut context = TraceContext::new(router, thread_stop, thread_metrics);
            let mut logfile: EVENT_TRACE_LOGFILEW = unsafe { std::mem::zeroed() };

            logfile.LoggerName = name_wide.as_mut_ptr();
            // Request real-time delivery, new `EVENT_RECORD` format, and unscaled raw QPC timestamps
            // so `EventHeader.TimeStamp` matches `StackWalk.EventTimeStamp` bit-for-bit.
            logfile.Anonymous1.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME
                | PROCESS_TRACE_MODE_EVENT_RECORD
                | PROCESS_TRACE_MODE_RAW_TIMESTAMP;
            logfile.Anonymous2.EventRecordCallback = Some(etw_event_callback::<R>);
            logfile.BufferCallback = Some(etw_buffer_callback::<R>);
            logfile.Context = &mut context as *mut TraceContext<R> as *mut c_void;

            // SAFETY: `logfile`, `name_wide`, and `context` remain pinned on this stack frame
            // until `ProcessTrace` returns and the trace handle is closed.
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

                // If `ProcessTrace` exited via `BufferCallback` returning 0 or session stop
                // before `ConsumerHandle::request_stop` was called, close the handle here.
                let prev = thread_handle_raw.swap(INVALID_TRACE_HANDLE, Ordering::AcqRel);
                if prev != INVALID_TRACE_HANDLE && prev != 0 {
                    CloseTrace(PROCESSTRACE_HANDLE { Value: prev });
                }

                status
            };

            // Flush any remaining counters from the final partial buffer before exiting.
            context.flush_metrics();

            if context.poisoned {
                return Err(EtwError::CallbackPanicked);
            }

            // `ERROR_CANCELLED` (1223) is returned when `BufferCallback` returns `FALSE` (0)
            // during normal shutdown; treat it as a clean exit alongside `ERROR_SUCCESS`.
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
