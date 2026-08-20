//! Correlation helper for pairing asynchronous ETW `Stack_Walk` events with trigger events.

use std::collections::HashMap;

use crate::pipeline::event::CorrelatedSyscallEvent;

/// Payload structure for an ETW `Stack_Walk` event (Opcode 32).
#[derive(Clone, Debug)]
pub struct StackWalkPayload {
    /// The timestamp of the original event that triggered this stack trace.
    /// This is the pairing key between trigger and stack.
    pub event_timestamp: u64,
    /// The process ID where the stack trace occurred.
    pub stack_process: u32,
    /// The thread ID where the stack trace occurred.
    pub stack_thread: u32,
    /// The number of instruction pointers (frames) in the stack.
    pub frame_count: usize,
    /// The actual memory addresses of the call stack frames.
    pub frames: Vec<u64>,
}

impl StackWalkPayload {
    /// Parses the raw binary payload of a `Stack_Walk` event.
    pub fn parse(user_data: &[u8]) -> Option<Self> {
        // A valid stack payload must have at least the timestamp (8 bytes),
        // process ID (4 bytes), and thread ID (4 bytes).
        if user_data.len() < 16 {
            return None;
        }

        // Extract the payload fields using the proper byte offsets
        let event_timestamp = u64::from_ne_bytes(user_data[0..8].try_into().unwrap());
        let stack_process = u32::from_ne_bytes(user_data[8..12].try_into().unwrap());
        let stack_thread = u32::from_ne_bytes(user_data[12..16].try_into().unwrap());

        // The remaining bytes are an array of 64-bit (8 byte) instruction pointers
        let frame_count = (user_data.len() - 16) / 8;

        let mut frames = Vec::with_capacity(frame_count);
        for i in 0..frame_count {
            let start = 16 + (i * 8);
            let ptr = u64::from_ne_bytes(user_data[start..start + 8].try_into().unwrap());
            frames.push(ptr);
        }

        Some(Self {
            event_timestamp,
            stack_process,
            stack_thread,
            frame_count,
            frames,
        })
    }
}

/// Pending trigger event waiting for its StackWalk pair.
#[derive(Debug, Clone)]
struct PendingTrigger {
    pid: u32,
    tid: u32,
    timestamp: i64,
    syscall_number: Option<u32>,
}

/// State machine designed to correlate trigger events with their ETW `Stack_Walk` events.
pub struct StackCorrelator {
    /// Holds trigger events waiting for their corresponding stack payload.
    /// Keyed by the trigger event's raw timestamp.
    pending_events: HashMap<u64, PendingTrigger>,
    /// Holds stack payloads waiting for their corresponding trigger event.
    /// Keyed by the `StackWalkPayload`'s `event_timestamp`.
    pending_stacks: HashMap<u64, StackWalkPayload>,
    /// Safety limit to prevent unbounded memory growth if events are lost.
    max_pending_items: usize,
}

impl StackCorrelator {
    /// Creates a new `StackCorrelator` with a maximum threshold for pending orphan items.
    pub fn new(max_pending_items: usize) -> Self {
        Self {
            pending_events: HashMap::new(),
            pending_stacks: HashMap::new(),
            max_pending_items,
        }
    }

    /// Ingests a syscall enter trigger event.
    pub fn process_syscall_trigger(
        &mut self,
        pid: u32,
        tid: u32,
        timestamp: i64,
        syscall_number: Option<u32>,
    ) -> Option<CorrelatedSyscallEvent> {
        let ts_key = timestamp as u64;

        // Check if stack payload already arrived earlier
        if let Some(stack) = self.pending_stacks.remove(&ts_key) {
            self.maintenance();
            return Some(CorrelatedSyscallEvent {
                pid,
                tid,
                timestamp,
                syscall_number,
                frames: stack.frames,
            });
        }

        // Store trigger waiting for stack
        self.pending_events.insert(
            ts_key,
            PendingTrigger {
                pid,
                tid,
                timestamp,
                syscall_number,
            },
        );

        self.maintenance();
        None
    }

    /// Ingests a `Stack_Walk` payload event.
    pub fn process_stack_walk(&mut self, payload: StackWalkPayload) -> Option<CorrelatedSyscallEvent> {
        let key = payload.event_timestamp;

        // Check if trigger event is already waiting for this stack
        if let Some(trigger) = self.pending_events.remove(&key) {
            self.maintenance();
            return Some(CorrelatedSyscallEvent {
                pid: trigger.pid,
                tid: trigger.tid,
                timestamp: trigger.timestamp,
                syscall_number: trigger.syscall_number,
                frames: payload.frames,
            });
        }

        // Otherwise store stack payload waiting for trigger
        self.pending_stacks.insert(key, payload);
        self.maintenance();
        None
    }

    /// Performs routine cleanup to prevent memory exhaustion caused by dropped or orphaned kernel events.
    fn maintenance(&mut self) {
        if self.pending_events.len() > self.max_pending_items {
            log::warn!(
                target: "stack_correlator",
                "Pending trigger events limit ({}) reached. Purging orphaned items.",
                self.max_pending_items
            );
            self.pending_events.clear();
        }
        if self.pending_stacks.len() > self.max_pending_items {
            log::warn!(
                target: "stack_correlator",
                "Pending stack payloads limit ({}) reached. Purging orphaned items.",
                self.max_pending_items
            );
            self.pending_stacks.clear();
        }
    }
}

impl Default for StackCorrelator {
    fn default() -> Self {
        Self::new(10_000)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests parsing valid and truncated StackWalk binary payloads.
    #[test]
    fn test_stack_walk_payload_parse() {
        // Truncated buffer (< 16 bytes)
        assert!(StackWalkPayload::parse(&[0u8; 15]).is_none());

        // Valid buffer: timestamp (8B) + PID (4B) + TID (4B) + 2 frames (16B)
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&100_000u64.to_ne_bytes()); // timestamp
        buffer.extend_from_slice(&1234u32.to_ne_bytes());    // PID
        buffer.extend_from_slice(&5678u32.to_ne_bytes());    // TID
        buffer.extend_from_slice(&0x7FFE_0001u64.to_ne_bytes()); // frame 1
        buffer.extend_from_slice(&0x7FFE_0002u64.to_ne_bytes()); // frame 2

        let parsed = StackWalkPayload::parse(&buffer).expect("Must parse valid payload");
        assert_eq!(parsed.event_timestamp, 100_000);
        assert_eq!(parsed.stack_process, 1234);
        assert_eq!(parsed.stack_thread, 5678);
        assert_eq!(parsed.frame_count, 2);
        assert_eq!(parsed.frames, vec![0x7FFE_0001, 0x7FFE_0002]);
    }

    /// Tests pairing when trigger event arrives before the stack walk event.
    #[test]
    fn test_trigger_before_stack_pairing() {
        let mut correlator = StackCorrelator::new(100);

        // 1. Trigger arrives
        let res1 = correlator.process_syscall_trigger(1234, 5678, 100_000, Some(0x28));
        assert!(res1.is_none());

        // 2. Stack arrives
        let payload = StackWalkPayload {
            event_timestamp: 100_000,
            stack_process: 1234,
            stack_thread: 5678,
            frame_count: 1,
            frames: vec![0x7FFF_1234_5678],
        };
        let res2 = correlator.process_stack_walk(payload).expect("Must correlate event");
        assert_eq!(res2.pid, 1234);
        assert_eq!(res2.tid, 5678);
        assert_eq!(res2.syscall_number, Some(0x28));
        assert_eq!(res2.frames, vec![0x7FFF_1234_5678]);
    }

    /// Tests pairing when stack walk event arrives before the trigger event.
    #[test]
    fn test_stack_before_trigger_pairing() {
        let mut correlator = StackCorrelator::new(100);

        // 1. Stack arrives first
        let payload = StackWalkPayload {
            event_timestamp: 200_000,
            stack_process: 9999,
            stack_thread: 8888,
            frame_count: 1,
            frames: vec![0x7FFF_AAAA_BBBB],
        };
        let res1 = correlator.process_stack_walk(payload);
        assert!(res1.is_none());

        // 2. Trigger arrives second
        let res2 = correlator
            .process_syscall_trigger(9999, 8888, 200_000, Some(0x50))
            .expect("Must correlate event");
        assert_eq!(res2.pid, 9999);
        assert_eq!(res2.tid, 8888);
        assert_eq!(res2.syscall_number, Some(0x50));
        assert_eq!(res2.frames, vec![0x7FFF_AAAA_BBBB]);
    }

    /// Tests capacity maintenance preventing memory leaks under orphaned bursts.
    #[test]
    fn test_stack_correlator_capacity_purge() {
        let mut correlator = StackCorrelator::new(2);

        // Insert 3 orphaned triggers (exceeding limit of 2)
        correlator.process_syscall_trigger(1, 1, 10, None);
        correlator.process_syscall_trigger(2, 2, 20, None);
        correlator.process_syscall_trigger(3, 3, 30, None);

        // Maintenance should purge pending items to bound memory
        assert_eq!(correlator.pending_events.len(), 0);
    }
}
