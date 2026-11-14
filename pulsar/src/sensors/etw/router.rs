//! Zero-copy event routing contract and batch-updated telemetry health metrics for ETW consumers.
//!
//! # Architectural Role & Dependency Inversion
//!
//! Previously, the low-level ETW consumer callback in `sensors::etw` imported pipeline GUID
//! constants and opcodes directly from `crate::pipeline::constants`, and cloned every matching
//! event's `UserData` into a `Vec<u8>` (`EventRecord`) before sending it over a single MPSC
//! channel.
//!
//! [`TraceRouter`] inverts that dependency: `sensors::etw` defines the abstract routing contract
//! and knows nothing about upper-layer schemas or channels. Upper layers (such as
//! [`PipelineEventRouter`](crate::pipeline::PipelineEventRouter)) implement [`TraceRouter`] to:
//! 1. Gate events on header fields (`ProviderId`, `Opcode`, `ProcessId`) at zero cost.
//! 2. Decode matching payloads in-place from `&RawEvent` using [`ByteCursor`](crate::pipeline::etw_schemas::ByteCursor).
//! 3. Route the decoded domain struct to priority-separated channels and return a [`ConsumerOutcome`].
//!
//! # Low-Overhead Batch Metrics
//!
//! Under heavy kernel telemetry (such as `PERF_SYSCALL` or `PERF_IMAGE_LOAD` bursts), executing
//! an atomic `fetch_add` on shared counters for every single event creates unnecessary cache-line
//! bouncing. Because `ProcessTrace` processes events sequentially per trace buffer and invokes
//! `BufferCallback` at the end of each buffer, [`TraceContext`](super::TraceContext) accumulates
//! [`ConsumerMetricsSnapshot`] in plain non-atomic fields on its stack frame and flushes them
//! into [`ConsumerMetrics`] once per buffer via [`ConsumerMetrics::record_batch`].

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{SyncSender, TrySendError};

use crate::sensors::etw::event::EventRecord;
use crate::sensors::etw::raw_event::RawEvent;

/// Outcome of processing a single [`RawEvent`] inside [`TraceRouter::on_event`].
///
/// Returned to [`TraceContext`](super::TraceContext) so the consumer loop can update its
/// per-buffer telemetry counters and detect channel disconnection without knowing the
/// concrete channel or sink types used by the router.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsumerOutcome {
    /// The event did not match the router's header filter (e.g., unmonitored provider GUID,
    /// ignored opcode, or self/Idle/System PID) and was discarded before payload parsing.
    FilteredOut,
    /// The event matched, was decoded without error, and was successfully enqueued into
    /// the destination channel or sink.
    Dispatched,
    /// The event was decoded, but dropped via non-blocking `try_send` because the bounded
    /// destination channel is currently at capacity.
    DroppedChannelFull,
    /// The destination channel's receiver has been dropped, signaling that the downstream
    /// pipeline is shutting down and the ETW consumer should terminate `ProcessTrace`.
    ChannelDisconnected,
    /// The event matched the header filter, but its binary `UserData` payload failed DTO
    /// or domain schema validation.
    ParseError,
}

/// Extension trait implemented by telemetry routers that inspect and decode zero-copy
/// [`RawEvent`] borrows directly inside the Win32 `ProcessTrace` callback.
///
/// # Behavioral Contract & Concurrency Invariants
///
/// * **Execution Context:** [`TraceRouter::on_event`] is invoked synchronously on the dedicated
///   `pulsar-etw-*` consumer thread for every event in the trace buffer.
/// * **Non-Blocking Requirement:** Implementors **must never block** (e.g., use `SyncSender::try_send`
///   rather than blocking `send`, and avoid mutexes or disk/network I/O). Blocking inside
///   `on_event` stalls `ProcessTrace` buffer draining and causes the Windows kernel to drop
///   entire real-time ETW buffers (`RealTimeBuffersLost`).
/// * **Panic Containment:** Although the consumer wraps `on_event` in `std::panic::catch_unwind`
///   to prevent undefined behavior across the `extern "system"` FFI boundary, panicking poisons
///   and terminates the consumer session. Implementors should return [`ConsumerOutcome::ParseError`]
///   on malformed payloads rather than panicking.
///
/// # Examples
///
/// Implementing a custom router for a specific provider and opcode:
///
/// ```
/// use pulsar::sensors::etw::{ConsumerOutcome, RawEvent, TraceRouter};
///
/// struct OpcodeFilterRouter {
///     target_opcode: u8,
/// }
///
/// impl TraceRouter for OpcodeFilterRouter {
///     fn on_event(&self, event: &RawEvent, current_pid: u32) -> ConsumerOutcome {
///         if event.process_id() == current_pid || event.opcode() != self.target_opcode {
///             return ConsumerOutcome::FilteredOut;
///         }
///         // Inspect `event.user_data()` in-place without heap allocation
///         if event.user_data().is_empty() {
///             return ConsumerOutcome::ParseError;
///         }
///         ConsumerOutcome::Dispatched
///     }
/// }
/// ```
pub trait TraceRouter: Send + Sync + 'static {
    /// Inspects, decodes, and routes a single zero-copy [`RawEvent`] emitted by ETW.
    ///
    /// # Arguments
    ///
    /// * `event` - Zero-copy view of the raw Win32 `EVENT_RECORD`, valid for the duration of this call.
    /// * `current_pid` - Cached Process ID (`std::process::id()`) of the running Pulsar agent so
    ///   implementors can filter out self-generated telemetry without a syscall per event.
    ///
    /// # Returns
    ///
    /// A [`ConsumerOutcome`] classifying how the event was handled for telemetry health accounting.
    fn on_event(&self, event: &RawEvent, current_pid: u32) -> ConsumerOutcome;
}

impl<F> TraceRouter for F
where
    F: Fn(&RawEvent, u32) -> ConsumerOutcome + Send + Sync + 'static,
{
    #[inline]
    fn on_event(&self, event: &RawEvent, current_pid: u32) -> ConsumerOutcome {
        (self)(event, current_pid)
    }
}

/// Blanket [`TraceRouter`] implementation for `SyncSender<EventRecord>`.
///
/// Enables standalone sensor tests and legacy callers to forward owned [`EventRecord`]
/// copies over a bounded channel while still benefiting from [`ConsumerHandle`](super::ConsumerHandle)
/// lifecycle management and metrics.
impl TraceRouter for SyncSender<EventRecord> {
    #[inline]
    fn on_event(&self, event: &RawEvent, _current_pid: u32) -> ConsumerOutcome {
        let record = EventRecord::from_raw_event(event);
        match self.try_send(record) {
            Ok(()) => ConsumerOutcome::Dispatched,
            Err(TrySendError::Full(_)) => ConsumerOutcome::DroppedChannelFull,
            Err(TrySendError::Disconnected(_)) => ConsumerOutcome::ChannelDisconnected,
        }
    }
}

/// Point-in-time value snapshot of ETW consumer callback counters.
///
/// Used both as the thread-local accumulator inside [`TraceContext`](super::TraceContext)
/// between buffer flushes and as the immutable snapshot returned to callers via
/// [`ConsumerMetrics::snapshot`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ConsumerMetricsSnapshot {
    /// Total number of raw events delivered to `etw_event_callback` by Windows.
    pub events_received: u64,
    /// Events discarded at the zero-copy header gate ([`ConsumerOutcome::FilteredOut`]).
    pub events_filtered_out: u64,
    /// Events decoded and successfully dispatched to pipeline channels ([`ConsumerOutcome::Dispatched`]).
    pub events_dispatched: u64,
    /// Events dropped because a bounded pipeline channel reached capacity ([`ConsumerOutcome::DroppedChannelFull`]).
    pub events_dropped_channel_full: u64,
    /// Events whose binary payload failed schema validation ([`ConsumerOutcome::ParseError`]).
    pub parse_errors: u64,
    /// Number of ETW trace buffers processed and flushed via `etw_buffer_callback`.
    pub buffers_processed: u64,
}

/// Shared, thread-safe (`Send + Sync`) atomic telemetry counters for an active ETW consumer.
///
/// # Concurrency & Batching Design
///
/// Each `ProcessTrace` loop runs on a single dedicated consumer thread, while external
/// monitoring threads (or shutdown teardown in `main.rs`) may read [`Self::snapshot`] at
/// any time. To avoid per-event atomic RMW instructions on the hot callback path, the
/// consumer thread increments a stack-local [`ConsumerMetricsSnapshot`] and flushes the
/// accumulated deltas once per ETW buffer via [`Self::record_batch`] using `Ordering::Relaxed`.
#[derive(Debug, Default)]
pub struct ConsumerMetrics {
    /// Total raw events received across all flushed buffers.
    events_received: AtomicU64,
    /// Total events rejected by the router's header filter.
    events_filtered_out: AtomicU64,
    /// Total events successfully decoded and sent to downstream channels.
    events_dispatched: AtomicU64,
    /// Total events dropped due to bounded channel backpressure.
    events_dropped_channel_full: AtomicU64,
    /// Total events that failed binary schema decoding.
    parse_errors: AtomicU64,
    /// Total ETW ring buffers drained by `ProcessTrace`.
    buffers_processed: AtomicU64,
}

impl ConsumerMetrics {
    /// Creates a new zero-initialized [`ConsumerMetrics`] instance.
    pub const fn new() -> Self {
        Self {
            events_received: AtomicU64::new(0),
            events_filtered_out: AtomicU64::new(0),
            events_dispatched: AtomicU64::new(0),
            events_dropped_channel_full: AtomicU64::new(0),
            parse_errors: AtomicU64::new(0),
            buffers_processed: AtomicU64::new(0),
        }
    }

    /// Atomically adds a thread-local batch of counters into the shared metrics and resets `batch` to zero.
    ///
    /// # Arguments
    ///
    /// * `batch` - Mutable reference to the consumer thread's local counter accumulator; all
    ///   non-zero fields are added to `self` and reset to `0`.
    #[inline]
    pub fn record_batch(&self, batch: &mut ConsumerMetricsSnapshot) {
        if batch.events_received > 0 {
            self.events_received
                .fetch_add(batch.events_received, Ordering::Relaxed);
            batch.events_received = 0;
        }
        if batch.events_filtered_out > 0 {
            self.events_filtered_out
                .fetch_add(batch.events_filtered_out, Ordering::Relaxed);
            batch.events_filtered_out = 0;
        }
        if batch.events_dispatched > 0 {
            self.events_dispatched
                .fetch_add(batch.events_dispatched, Ordering::Relaxed);
            batch.events_dispatched = 0;
        }
        if batch.events_dropped_channel_full > 0 {
            self.events_dropped_channel_full
                .fetch_add(batch.events_dropped_channel_full, Ordering::Relaxed);
            batch.events_dropped_channel_full = 0;
        }
        if batch.parse_errors > 0 {
            self.parse_errors
                .fetch_add(batch.parse_errors, Ordering::Relaxed);
            batch.parse_errors = 0;
        }
        if batch.buffers_processed > 0 {
            self.buffers_processed
                .fetch_add(batch.buffers_processed, Ordering::Relaxed);
            batch.buffers_processed = 0;
        }
    }

    /// Reads a point-in-time [`ConsumerMetricsSnapshot`] of all atomic counters.
    #[inline]
    pub fn snapshot(&self) -> ConsumerMetricsSnapshot {
        ConsumerMetricsSnapshot {
            events_received: self.events_received.load(Ordering::Relaxed),
            events_filtered_out: self.events_filtered_out.load(Ordering::Relaxed),
            events_dispatched: self.events_dispatched.load(Ordering::Relaxed),
            events_dropped_channel_full: self.events_dropped_channel_full.load(Ordering::Relaxed),
            parse_errors: self.parse_errors.load(Ordering::Relaxed),
            buffers_processed: self.buffers_processed.load(Ordering::Relaxed),
        }
    }
}
