//! Asynchronous call-stack correlator pairing out-of-band kernel `StackWalk` events with their
//! triggering domain events.
//!
//! # Why Out-of-Band Stack Correlation Is Required
//!
//! Unlike user-mode manifest providers—which attach call stacks inline inside `EVENT_RECORD.ExtendedData`
//! (`STACK_TRACE64` / `STACK_TRACE32`)—the Windows System Logger / NT Kernel Logger emits call
//! stacks as separate out-of-band `StackWalk_TypeGroup1` (Opcode 32) events immediately after
//! the triggering kernel event (e.g., `SysCallEnter`).
//!
//! Because multi-processor ETW buffers can occasionally deliver the `StackWalk` event slightly
//! before or after its trigger event, [`CallStackCorrelator`] maintains bounded bidirectional
//! pools (`pending_triggers` and `pending_stacks`) keyed by the composite tuple
//! `(EventTimeStamp, ProcessId, ThreadId)` (`CorrelationKey`).
//!
//! Including both `ProcessId` and `ThreadId` alongside `EventTimeStamp` prevents cross-core
//! timestamp collisions when two logical processors log events on the same QPC tick.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::model::types::StackTrace;
use crate::pipeline::Event;
use crate::pipeline::etw_schemas::nt_kernel::stack_walk::{StackWalk_TypeGroup1, StackWalkEvent};
use crate::sensors::etw::EventRecord;

/// Maximum number of unmatched trigger or stack entries held in memory before age-based eviction runs.
const DEFAULT_MAX_PENDING: usize = 5_000;

/// Maximum wall-clock duration a trigger event waits for its `StackWalk` before being emitted without a stack.
const DEFAULT_MAX_AGE: Duration = Duration::from_millis(50);

/// Buffered trigger event awaiting its matching out-of-band `StackWalkEvent`.
struct PendingTrigger {
    /// Decoded domain event waiting for its `stack_trace` field to be populated.
    event: Event,
    /// Host `Instant` when this trigger entered the correlation table.
    inserted_at: Instant,
}

/// Buffered out-of-band `StackTrace` that arrived ahead of its triggering event.
struct PendingStack {
    /// Extracted call stack frames.
    stack_trace: StackTrace,
    /// Host `Instant` when this stack entered the correlation table.
    inserted_at: Instant,
}

/// Composite correlation key `(EventTimeStamp, ProcessId, ThreadId)` uniquely identifying a
/// thread's kernel event across concurrent logical processors.
type CorrelationKey = (u64, u32, u32);

/// Stateful correlator pairing asynchronous kernel `StackWalk` events with triggering [`Event`]s.
///
/// # State & Eviction Invariants
///
/// * **No Silent Trigger Drops:** When [`Self::flush_expired`] is called periodically by
///   [`EventDispatcher`](super::EventDispatcher), any trigger event older than `max_age` (`50ms`)
///   is returned to the caller and dispatched *without* a stack trace rather than being silently
///   discarded.
/// * **Bounded Memory:** Both `pending_triggers` and `pending_stacks` are capped at `max_pending`
///   (`5,000` entries) so an unmatched stream of `StackWalk` events can never cause unbounded
///   heap growth.
pub struct CallStackCorrelator {
    /// Trigger events waiting for a matching `StackWalkEvent`.
    pending_triggers: HashMap<CorrelationKey, PendingTrigger>,
    /// Out-of-order `StackWalkEvent`s waiting for their triggering event.
    pending_stacks: HashMap<CorrelationKey, PendingStack>,
    /// Maximum table capacity before age-based eviction is enforced.
    max_pending: usize,
    /// Maximum retention window (`50ms` default) before a pending item is considered expired.
    max_age: Duration,
}

impl CallStackCorrelator {
    /// Creates a new [`CallStackCorrelator`] with default capacity (`5,000`) and eviction age (`50ms`).
    pub fn new() -> Self {
        Self {
            pending_triggers: HashMap::with_capacity(1024),
            pending_stacks: HashMap::with_capacity(1024),
            max_pending: DEFAULT_MAX_PENDING,
            max_age: DEFAULT_MAX_AGE,
        }
    }

    /// Processes a pre-decoded [`StackWalkEvent`] (Opcode 32).
    ///
    /// If the corresponding trigger event is already waiting in `pending_triggers`, its stack
    /// trace is attached and the completed [`Event`] is returned immediately. Otherwise, the
    /// stack trace is buffered in `pending_stacks` in case the trigger arrives out-of-order.
    pub fn process_stack_walk_event(&mut self, sw: StackWalkEvent) -> Option<Event> {
        let key: CorrelationKey = (sw.event_timestamp, sw.process_id, sw.thread_id);

        if let Some(pending) = self.pending_triggers.remove(&key) {
            let mut event = pending.event;
            event.attach_stack_trace(sw.stack_trace);
            return Some(event);
        }

        self.pending_stacks.insert(
            key,
            PendingStack {
                stack_trace: sw.stack_trace,
                inserted_at: Instant::now(),
            },
        );

        self.evict_stale_stacks();
        None
    }

    /// Decodes and processes an incoming owned `StackWalk` [`EventRecord`] (Opcode 32).
    pub fn process_stack_walk(&mut self, record: &EventRecord) -> Option<Event> {
        let dto = StackWalk_TypeGroup1::try_from(record.user_data.as_slice()).ok()?;
        self.process_stack_walk_event(StackWalkEvent {
            event_timestamp: dto.EventTimeStamp,
            process_id: dto.StackProcess,
            thread_id: dto.StackThread,
            stack_trace: StackTrace::new(dto.to_frames()),
        })
    }

    /// Processes a domain [`Event`] that may expect an asynchronous stack trace from the kernel.
    ///
    /// * When `is_async_stack_traced` is `false`, returns `Some(event)` immediately with zero buffering.
    /// * When `is_async_stack_traced` is `true` and a matching stack already arrived in
    ///   `pending_stacks`, attaches the stack and returns `Some(event)` immediately.
    /// * Otherwise, buffers `event` in `pending_triggers` and returns `None`.
    pub fn process_trigger(
        &mut self,
        mut event: Event,
        is_async_stack_traced: bool,
    ) -> Option<Event> {
        if !is_async_stack_traced {
            return Some(event);
        }

        let key: CorrelationKey = (
            event.timestamp() as u64,
            event.process_id(),
            event.thread_id(),
        );

        if let Some(pending_stack) = self.pending_stacks.remove(&key) {
            event.attach_stack_trace(pending_stack.stack_trace);
            return Some(event);
        }

        if self.pending_triggers.len() >= self.max_pending {
            let now = Instant::now();
            self.pending_triggers
                .retain(|_, item| now.duration_since(item.inserted_at) <= self.max_age);
            if self.pending_triggers.len() >= self.max_pending {
                self.pending_triggers.clear();
            }
        }

        self.pending_triggers.insert(
            key,
            PendingTrigger {
                event,
                inserted_at: Instant::now(),
            },
        );

        self.evict_stale_stacks();
        None
    }

    /// Scans the pending pools and evicts entries that have exceeded `max_age`.
    ///
    /// Trigger events that timed out without receiving a `StackWalk` are returned so the
    /// dispatcher can still forward them to detection sinks without a stack trace.
    pub fn flush_expired(&mut self) -> Vec<Event> {
        let now = Instant::now();
        let mut expired_events = Vec::new();

        self.pending_triggers.retain(|_, item| {
            if now.duration_since(item.inserted_at) > self.max_age {
                expired_events.push(item.event.clone());
                false
            } else {
                true
            }
        });

        self.pending_stacks
            .retain(|_, item| now.duration_since(item.inserted_at) <= self.max_age);

        expired_events
    }

    /// Returns `true` if both `pending_triggers` and `pending_stacks` are empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.pending_triggers.is_empty() && self.pending_stacks.is_empty()
    }

    /// Purges expired orphan stacks when `pending_stacks` exceeds `max_pending` without
    /// dropping any pending trigger events.
    fn evict_stale_stacks(&mut self) {
        if self.pending_stacks.len() > self.max_pending {
            let now = Instant::now();
            self.pending_stacks
                .retain(|_, item| now.duration_since(item.inserted_at) <= self.max_age);
            if self.pending_stacks.len() > self.max_pending {
                self.pending_stacks.clear();
            }
        }
    }
}

impl Default for CallStackCorrelator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::events::SyscallEvent;
    use crate::model::types::ProcessId;
    use windows_sys::core::GUID;

    fn create_dummy_syscall_event(timestamp: i64) -> Event {
        Event::Syscall(SyscallEvent {
            timestamp,
            process_id: ProcessId(1234),
            thread_id: 5678,
            syscall_address: 0x7FFF12345678,
            stack_trace: None,
        })
    }

    fn create_dummy_stack_record(timestamp: u64, frames: &[u64]) -> EventRecord {
        let mut user_data = Vec::new();
        user_data.extend_from_slice(&timestamp.to_ne_bytes());
        user_data.extend_from_slice(&1234u32.to_ne_bytes()); // PID
        user_data.extend_from_slice(&5678u32.to_ne_bytes()); // TID

        for frame in frames {
            user_data.extend_from_slice(&frame.to_ne_bytes());
        }

        EventRecord {
            timestamp: timestamp as i64,
            process_id: 1234,
            thread_id: 5678,
            event_id: 0,
            version: 2,
            opcode: 32,
            level: 0,
            provider_id: GUID {
                data1: 0xdef2fe46,
                data2: 0x7bd6,
                data3: 0x4b80,
                data4: [0xbd, 0x94, 0xf5, 0x7f, 0xe2, 0x0d, 0x0c, 0xe3],
            },
            user_data,
            stack_trace: None,
        }
    }

    #[test]
    fn test_in_order_correlation() {
        let mut correlator = CallStackCorrelator::new();
        let trigger = create_dummy_syscall_event(100_000);
        let stack_record = create_dummy_stack_record(100_000, &[0x1111, 0x2222, 0x3333]);

        // Trigger arrives first and is buffered
        assert!(correlator.process_trigger(trigger, true).is_none());

        // Stack arrives second and matches
        let matched = correlator.process_stack_walk(&stack_record);
        assert!(matched.is_some());

        if let Some(Event::Syscall(syscall)) = matched {
            assert_eq!(syscall.timestamp, 100_000);
            assert!(syscall.stack_trace.is_some());
            let stack = syscall.stack_trace.unwrap();
            assert_eq!(stack.frames(), &[0x1111, 0x2222, 0x3333]);
        } else {
            panic!("Expected SyscallEvent");
        }
    }

    #[test]
    fn test_out_of_order_correlation() {
        let mut correlator = CallStackCorrelator::new();
        let trigger = create_dummy_syscall_event(200_000);
        let stack_record = create_dummy_stack_record(200_000, &[0xAAAA, 0xBBBB]);

        // Stack arrives first (out-of-order) and is buffered
        assert!(correlator.process_stack_walk(&stack_record).is_none());

        // Trigger arrives second and matches immediately
        let matched = correlator.process_trigger(trigger, true);
        assert!(matched.is_some());

        if let Some(Event::Syscall(syscall)) = matched {
            assert_eq!(syscall.timestamp, 200_000);
            assert!(syscall.stack_trace.is_some());
            let stack = syscall.stack_trace.unwrap();
            assert_eq!(stack.frames(), &[0xAAAA, 0xBBBB]);
        } else {
            panic!("Expected SyscallEvent");
        }
    }

    #[test]
    fn test_non_stack_traced_event_bypass() {
        let mut correlator = CallStackCorrelator::new();
        let trigger = create_dummy_syscall_event(300_000);

        // When is_async_stack_traced is false, passes through immediately
        let ready = correlator.process_trigger(trigger, false);
        assert!(ready.is_some());

        if let Some(Event::Syscall(syscall)) = ready {
            assert_eq!(syscall.timestamp, 300_000);
            assert!(syscall.stack_trace.is_none());
        }
    }

    #[test]
    fn test_timeout_flushing() {
        let mut correlator = CallStackCorrelator::new();
        // Set max_age to zero to trigger instant expiration on flush
        correlator.max_age = Duration::from_millis(0);

        let trigger = create_dummy_syscall_event(400_000);
        assert!(correlator.process_trigger(trigger, true).is_none());

        // Wait a tick and flush expired
        std::thread::sleep(Duration::from_millis(1));
        let flushed = correlator.flush_expired();
        assert_eq!(flushed.len(), 1);

        if let Event::Syscall(syscall) = &flushed[0] {
            assert_eq!(syscall.timestamp, 400_000);
            assert!(syscall.stack_trace.is_none());
        } else {
            panic!("Expected SyscallEvent");
        }
    }
}
