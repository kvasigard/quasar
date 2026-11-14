//! Zero-copy event routing contract and low-overhead telemetry health metrics for ETW consumers.
//!
//! [`TraceRouter`] decouples the low-level Win32 `ProcessTrace` callback in `sensors::etw`
//! from upper-layer pipeline schemas and channel topologies. Implementors inspect the
//! borrowed [`RawEvent`] header, decode matching events in-place without allocating a
//! `Vec<u8>` copy of `UserData`, and return a [`ConsumerOutcome`] so the consumer thread
//! can batch-update [`ConsumerMetrics`] once per ETW buffer.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{SyncSender, TrySendError};

use crate::sensors::etw::event::EventRecord;
use crate::sensors::etw::raw_event::RawEvent;

/// Outcome of processing a single [`RawEvent`] inside [`TraceRouter::on_event`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsumerOutcome {
    /// Event was discarded at the header gate (unmonitored provider, opcode, or self/system PID).
    FilteredOut,
    /// Event was decoded and enqueued into the target channel or sink.
    Dispatched,
    /// Event was decoded, but dropped because the bounded destination channel is full.
    DroppedChannelFull,
    /// The destination channel receiver has disconnected; signals the consumer to stop.
    ChannelDisconnected,
    /// Event matched the header gate, but its binary payload failed schema decoding.
    ParseError,
}

/// Trait implemented by telemetry routers that process zero-copy [`RawEvent`] borrows
/// directly inside the ETW `ProcessTrace` callback.
pub trait TraceRouter: Send + Sync + 'static {
    /// Processes a single zero-copy [`RawEvent`] emitted by ETW.
    ///
    /// # Arguments
    ///
    /// * `event` - Zero-copy view of the raw Win32 `EVENT_RECORD`.
    /// * `current_pid` - Process ID of the running Pulsar agent for self-filtering.
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

/// Blanketed [`TraceRouter`] implementation for a raw `SyncSender<EventRecord>` channel,
/// allowing standalone ETW sensor tests or raw record consumers to forward owned [`EventRecord`]s.
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

/// Point-in-time snapshot of ETW consumer callback counters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ConsumerMetricsSnapshot {
    /// Total number of raw events delivered to `etw_callback` by Windows.
    pub events_received: u64,
    /// Events discarded at the zero-copy header gate.
    pub events_filtered_out: u64,
    /// Events decoded and successfully dispatched to pipeline channels.
    pub events_dispatched: u64,
    /// Events dropped because a bounded pipeline channel reached capacity.
    pub events_dropped_channel_full: u64,
    /// Events whose binary payload failed schema validation.
    pub parse_errors: u64,
    /// Number of ETW trace buffers processed by `ProcessTrace`.
    pub buffers_processed: u64,
}

/// Shared atomic telemetry counters updated in batches per ETW buffer flush.
///
/// Because `etw_callback` runs on a single thread per `ProcessTrace` handle, the consumer
/// accumulates counters in non-atomic thread-local fields and flushes them into [`ConsumerMetrics`]
/// inside `etw_buffer_callback` (and on consumer exit), avoiding per-event atomic bus traffic.
#[derive(Debug, Default)]
pub struct ConsumerMetrics {
    events_received: AtomicU64,
    events_filtered_out: AtomicU64,
    events_dispatched: AtomicU64,
    events_dropped_channel_full: AtomicU64,
    parse_errors: AtomicU64,
    buffers_processed: AtomicU64,
}

impl ConsumerMetrics {
    /// Creates a new zeroed [`ConsumerMetrics`] instance.
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

    /// Atomically adds a local batch of counters into the shared metrics.
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

    /// Reads a point-in-time snapshot of all consumer counters.
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
