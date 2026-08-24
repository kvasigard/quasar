//! Correlation helper for pairing asynchronous ETW `Stack_Walk` events with trigger events.

use std::collections::HashMap;

use crate::pipeline::event::CorrelatedSyscallEvent;

/// Maximum number of in-flight correlation items retained in memory.
pub const DEFAULT_MAX_PENDING_CORRELATION_ITEMS: usize = 50_000;
/// Maximum age in timestamp ticks before an un-paired trigger or stack is considered orphaned.
/// 2.0 seconds in 100ns units = 20_000_000 ticks.
pub const DEFAULT_ORPHAN_TTL_TICKS: u64 = 20_000_000;
/// Periodic maintenance interval (in operations) using fast bitwise mask (1,024 ops).
const MAINTENANCE_INTERVAL_MASK: u64 = 0x3FF;

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
    syscall_address: Option<u64>,
}

/// High-performance state machine designed to correlate trigger events with their ETW `Stack_Walk` events.
///
/// Uses sliding-window TTL eviction and periodic pruning to prevent dropping live in-flight pairs
/// during multi-threaded bursts.
pub struct StackCorrelator {
    /// Holds trigger events waiting for their corresponding stack payload.
    /// Keyed by the trigger event's raw timestamp.
    pending_events: HashMap<u64, PendingTrigger>,
    /// Holds stack payloads waiting for their corresponding trigger event.
    /// Keyed by the `StackWalkPayload`'s `event_timestamp`.
    pending_stacks: HashMap<u64, StackWalkPayload>,
    /// Maximum threshold for pending orphan items before force-eviction.
    max_pending_items: usize,
    /// Maximum age in ticks before an orphan is pruned.
    orphan_ttl_ticks: u64,
    /// Latest observed timestamp across trigger or stack events.
    latest_timestamp: u64,
    /// Operations counter used to schedule periodic maintenance.
    op_counter: u64,
}

impl StackCorrelator {
    /// Creates a new `StackCorrelator` with a maximum threshold for pending orphan items.
    pub fn new(max_pending_items: usize) -> Self {
        Self {
            pending_events: HashMap::new(),
            pending_stacks: HashMap::new(),
            max_pending_items,
            orphan_ttl_ticks: DEFAULT_ORPHAN_TTL_TICKS,
            latest_timestamp: 0,
            op_counter: 0,
        }
    }

    /// Sets a custom TTL threshold in ticks for orphaned items.
    pub fn with_ttl(mut self, ttl_ticks: u64) -> Self {
        self.orphan_ttl_ticks = ttl_ticks;
        self
    }

    /// Ingests a syscall enter trigger event.
    #[tracing::instrument(name = "correlate_syscall_trigger", skip(self), level = "trace")]
    pub fn process_syscall_trigger(
        &mut self,
        pid: u32,
        tid: u32,
        timestamp: i64,
        syscall_address: Option<u64>,
    ) -> Option<CorrelatedSyscallEvent> {
        let ts_key = timestamp as u64;
        self.latest_timestamp = self.latest_timestamp.max(ts_key);
        self.op_counter = self.op_counter.wrapping_add(1);

        if (self.op_counter & MAINTENANCE_INTERVAL_MASK) == 0 {
            self.maintenance();
        }

        // Check if stack payload already arrived earlier
        if let Some(stack) = self.pending_stacks.remove(&ts_key) {
            let resolved_pid = if pid != u32::MAX && pid != 0 {
                pid
            } else {
                stack.stack_process
            };
            let resolved_tid = if tid != u32::MAX && tid != 0 {
                tid
            } else {
                stack.stack_thread
            };
            return Some(CorrelatedSyscallEvent {
                pid: resolved_pid,
                tid: resolved_tid,
                timestamp,
                syscall_address,
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
                syscall_address,
            },
        );

        None
    }

    /// Ingests a `Stack_Walk` payload event.
    #[tracing::instrument(name = "correlate_stack_walk", skip(self, payload), level = "trace")]
    pub fn process_stack_walk(&mut self, payload: StackWalkPayload) -> Option<CorrelatedSyscallEvent> {
        let key = payload.event_timestamp;
        self.latest_timestamp = self.latest_timestamp.max(key);
        self.op_counter = self.op_counter.wrapping_add(1);

        if (self.op_counter & MAINTENANCE_INTERVAL_MASK) == 0 {
            self.maintenance();
        }

        // Check if trigger event is already waiting for this stack
        if let Some(trigger) = self.pending_events.remove(&key) {
            let resolved_pid = if payload.stack_process != 0 && payload.stack_process != u32::MAX {
                payload.stack_process
            } else {
                trigger.pid
            };
            let resolved_tid = if payload.stack_thread != 0 && payload.stack_thread != u32::MAX {
                payload.stack_thread
            } else {
                trigger.tid
            };
            return Some(CorrelatedSyscallEvent {
                pid: resolved_pid,
                tid: resolved_tid,
                timestamp: trigger.timestamp,
                syscall_address: trigger.syscall_address,
                frames: payload.frames,
            });
        }

        // Otherwise store stack payload waiting for trigger
        self.pending_stacks.insert(key, payload);
        None
    }

    /// Performs routine cleanup to prune expired orphaned items via a sliding-window TTL.
    ///
    /// Unlike a destructive complete purge, this preserves live in-flight pairs and only
    /// removes stale events that exceeded the correlation timeout.
    pub fn maintenance(&mut self) {
        let cutoff = self.latest_timestamp.saturating_sub(self.orphan_ttl_ticks);

        if cutoff > 0 {
            self.pending_events.retain(|&ts, _| ts >= cutoff);
            self.pending_stacks.retain(|&ts, _| ts >= cutoff);
        }

        // Hard capacity safety guard: if still over limit after TTL prune, remove oldest entries
        if self.pending_events.len() > self.max_pending_items {
            let excess = self.pending_events.len() - self.max_pending_items;
            let mut keys: Vec<u64> = self.pending_events.keys().copied().collect();
            keys.sort_unstable();
            for k in keys.into_iter().take(excess) {
                self.pending_events.remove(&k);
            }
        }

        if self.pending_stacks.len() > self.max_pending_items {
            let excess = self.pending_stacks.len() - self.max_pending_items;
            let mut keys: Vec<u64> = self.pending_stacks.keys().copied().collect();
            keys.sort_unstable();
            for k in keys.into_iter().take(excess) {
                self.pending_stacks.remove(&k);
            }
        }
    }
}

impl Default for StackCorrelator {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_PENDING_CORRELATION_ITEMS)
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
        buffer.extend_from_slice(&0x7FFE_0000_1000u64.to_ne_bytes());
        buffer.extend_from_slice(&0x7FFE_0000_2000u64.to_ne_bytes());

        let payload = StackWalkPayload::parse(&buffer).expect("Must parse successfully");
        assert_eq!(payload.event_timestamp, 100_000);
        assert_eq!(payload.stack_process, 1234);
        assert_eq!(payload.stack_thread, 5678);
        assert_eq!(payload.frame_count, 2);
        assert_eq!(
            payload.frames,
            vec![0x7FFE_0000_1000u64, 0x7FFE_0000_2000u64]
        );
    }

    /// Tests pairing when trigger event arrives before the stack walk event.
    #[test]
    fn test_trigger_before_stack_pairing() {
        let mut correlator = StackCorrelator::new(100);
        let ts = 200_000;

        // 1. Syscall trigger arrives
        let res1 = correlator.process_syscall_trigger(1000, 2000, ts, Some(0x28));
        assert!(res1.is_none());

        // 2. StackWalk arrives
        let payload = StackWalkPayload {
            event_timestamp: ts as u64,
            stack_process: 1000,
            stack_thread: 2000,
            frame_count: 1,
            frames: vec![0x7FFF_1234_5678],
        };
        let res2 = correlator.process_stack_walk(payload).expect("Must pair");
        assert_eq!(res2.pid, 1000);
        assert_eq!(res2.tid, 2000);
        assert_eq!(res2.timestamp, ts);
        assert_eq!(res2.syscall_address, Some(0x28));
        assert_eq!(res2.frames, vec![0x7FFF_1234_5678]);
    }

    /// Tests pairing when stack walk event arrives before the trigger event.
    #[test]
    fn test_stack_before_trigger_pairing() {
        let mut correlator = StackCorrelator::new(100);
        let ts = 300_000;

        // 1. StackWalk arrives first
        let payload = StackWalkPayload {
            event_timestamp: ts as u64,
            stack_process: 1000,
            stack_thread: 2000,
            frame_count: 1,
            frames: vec![0x7FFF_1234_5678],
        };
        let res1 = correlator.process_stack_walk(payload);
        assert!(res1.is_none());

        // 2. Syscall trigger arrives
        let res2 = correlator
            .process_syscall_trigger(1000, 2000, ts, Some(0x28))
            .expect("Must pair");
        assert_eq!(res2.pid, 1000);
        assert_eq!(res2.frames, vec![0x7FFF_1234_5678]);
    }

    /// Tests sliding-window TTL eviction and hard capacity limit pruning.
    #[test]
    fn test_stack_correlator_sliding_window_ttl_prune() {
        let mut correlator = StackCorrelator::new(2).with_ttl(1_000); // 1,000 tick TTL

        // Insert orphan event at timestamp 1,000
        correlator.process_syscall_trigger(1001, 2001, 1_000, None);
        assert_eq!(correlator.pending_events.len(), 1);

        // Insert new event at timestamp 3,000 (diff is 2,000 > 1,000 TTL)
        correlator.process_syscall_trigger(1002, 2002, 3_000, None);
        correlator.maintenance();

        // Expired item at ts 1,000 was pruned by sliding window
        assert_eq!(correlator.pending_events.len(), 1);
        assert!(correlator.pending_events.contains_key(&3_000));
    }
}
