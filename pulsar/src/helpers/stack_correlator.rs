//! Correlation helper for pairing asynchronous ETW `Stack_Walk` events with trigger events.

use std::collections::HashMap;
use std::sync::Arc;

use crate::pipeline::Event;
use crate::sensors::etw::EventRecord;

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
    ///
    /// # Arguments
    ///
    /// * `user_data` - The raw byte slice from the ETW event record.
    ///
    /// # Returns
    ///
    /// `Some(StackWalkPayload)` if the payload has valid header and frame structure, otherwise `None`.
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

        // Extract the actual instruction pointers
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

/// State machine designed to correlate trigger events with their ETW `Stack_Walk` events.
pub struct StackCorrelator {
    /// Holds trigger events waiting for their corresponding stack payload.
    /// Keyed by the trigger event's raw timestamp.
    pending_events: HashMap<u64, Arc<Event>>,
    /// Holds stack payloads waiting for their corresponding trigger event.
    /// Keyed by the `StackWalkPayload`'s `event_timestamp`.
    pending_stacks: HashMap<u64, StackWalkPayload>,
    /// Safety limit to prevent unbounded memory growth if events are lost.
    max_pending_items: usize,
}

impl StackCorrelator {
    /// Creates a new `StackCorrelator` with a maximum threshold for pending orphan items.
    ///
    /// # Arguments
    ///
    /// * `max_pending_items` - Maximum number of unassociated events before initiating maintenance.
    pub fn new(max_pending_items: usize) -> Self {
        Self {
            pending_events: HashMap::new(),
            pending_stacks: HashMap::new(),
            max_pending_items,
        }
    }

    /// Feeds an event into the correlator.
    ///
    /// # Arguments
    ///
    /// * `event` - The pipeline event reference.
    /// * `record` - The underlying ETW event record.
    ///
    /// # Returns
    ///
    /// `Some((OriginalEvent, StackWalkPayload))` if a match is successfully formed, otherwise `None`.
    pub fn process_event(
        &mut self,
        event: &Arc<Event>,
        record: &EventRecord,
    ) -> Option<(Arc<Event>, StackWalkPayload)> {
        let ts = record.timestamp as u64;
        let mut matched_pair = None;

        // Fast check to determine if the incoming event is a Stack_Walk
        // GUID: DEF2FE46-7BD6-4B80-BD94-F57FE20D0CE3 | Opcode: 32
        let is_stackwalk = record.opcode == 32 && record.provider_id.data1 == 0xdef2fe46;

        if is_stackwalk {
            if let Some(payload) = StackWalkPayload::parse(&record.user_data) {
                // Check if trigger event is already waiting for this stack
                if let Some(original_event) = self.pending_events.remove(&payload.event_timestamp) {
                    matched_pair = Some((original_event, payload));
                } else {
                    // Stacks may arrive slightly before or out-of-order relative to trigger events
                    self.pending_stacks.insert(payload.event_timestamp, payload);
                }
            }
        } else {
            // Check if stack payload arrived prior to this trigger
            if let Some(payload) = self.pending_stacks.remove(&ts) {
                matched_pair = Some((Arc::clone(event), payload));
            } else {
                // Store trigger event waiting for corresponding stack trace
                self.pending_events.insert(ts, Arc::clone(event));
            }
        }

        self.maintenance();
        matched_pair
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
