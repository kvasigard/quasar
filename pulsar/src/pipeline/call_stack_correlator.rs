//! Call stack correlator for pairing asynchronous ETW `StackWalk` events emitted by the NT Kernel Logger
//! with their triggering domain events.
//!
//! Because the NT Kernel Logger emits stack traces as separate out-of-band events, they must be correlated.
//! This correlation is achieved by matching the triggering event's timestamp with the `EventTimeStamp`
//! in the stack walk payload.
//!
//! Manifest-based and TraceLogging ETW providers attach call stacks directly inside `EventRecord`
//! extended data and do not require external correlation.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::model::types::StackTrace;
use crate::pipeline::Event;
use crate::pipeline::etw_schemas::nt_kernel::stack_walk::StackWalk_TypeGroup1;
use crate::sensors::etw::EventRecord;

/// Maximum number of unassociated items kept before evicting expired entries.
const DEFAULT_MAX_PENDING: usize = 5_000;

/// Maximum time an event waits for a stack walk before being emitted without a stack.
const DEFAULT_MAX_AGE: Duration = Duration::from_millis(50);

struct PendingTrigger {
    event: Event,
    inserted_at: Instant,
}

struct PendingStack {
    stack_trace: StackTrace,
    inserted_at: Instant,
}

/// Correlates asynchronous ETW StackWalk records with triggering domain events.
///
/// Designed for the NT Kernel Logger where stack walking is emitted as an out-of-band event
/// with a matching `EventTimeStamp`.
pub struct CallStackCorrelator {
    pending_triggers: HashMap<u64, PendingTrigger>,
    pending_stacks: HashMap<u64, PendingStack>,
    max_pending: usize,
    max_age: Duration,
}

impl CallStackCorrelator {
    /// Creates a new `CallStackCorrelator` with default capacity and eviction settings.
    pub fn new() -> Self {
        Self {
            pending_triggers: HashMap::with_capacity(1024),
            pending_stacks: HashMap::with_capacity(1024),
            max_pending: DEFAULT_MAX_PENDING,
            max_age: DEFAULT_MAX_AGE,
        }
    }

    /// Processes an incoming raw `StackWalk` event record (Opcode 32).
    ///
    /// If the corresponding trigger event has already been buffered, the stack trace is attached
    /// and the completed `Event` is returned immediately. Otherwise, the stack trace is stored
    /// in the pending stack pool awaiting the trigger event.
    pub fn process_stack_walk(&mut self, record: &EventRecord) -> Option<Event> {
        let dto = StackWalk_TypeGroup1::try_from(record.user_data.as_slice()).ok()?;
        let timestamp_key = dto.EventTimeStamp;
        let stack_trace = StackTrace::new(dto.to_frames());

        if let Some(pending) = self.pending_triggers.remove(&timestamp_key) {
            let mut event = pending.event;
            event.attach_stack_trace(stack_trace);
            return Some(event);
        }

        self.pending_stacks.insert(
            timestamp_key,
            PendingStack {
                stack_trace,
                inserted_at: Instant::now(),
            },
        );

        self.evict_stale();
        None
    }

    /// Processes an event that expects an asynchronous stack trace from the kernel.
    ///
    /// If the matching stack trace has already arrived out-of-order, it is attached immediately
    /// and returned. Otherwise, the trigger event is buffered awaiting the `StackWalk` record.
    pub fn process_trigger(
        &mut self,
        mut event: Event,
        is_async_stack_traced: bool,
    ) -> Option<Event> {
        if !is_async_stack_traced {
            return Some(event);
        }

        let timestamp_key = event.timestamp() as u64;

        if let Some(pending_stack) = self.pending_stacks.remove(&timestamp_key) {
            event.attach_stack_trace(pending_stack.stack_trace);
            return Some(event);
        }

        self.pending_triggers.insert(
            timestamp_key,
            PendingTrigger {
                event,
                inserted_at: Instant::now(),
            },
        );

        self.evict_stale();
        None
    }

    /// Scans the pending pools and evicts entries that have exceeded `max_age`.
    ///
    /// Trigger events that timed out without receiving a stack walk are returned so they can be
    /// forwarded to listeners without a stack trace, preventing event loss.
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

    /// Enforces the memory threshold by purging oldest entries when capacity is reached.
    fn evict_stale(&mut self) {
        if self.pending_triggers.len() > self.max_pending
            || self.pending_stacks.len() > self.max_pending
        {
            self.flush_expired();
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
