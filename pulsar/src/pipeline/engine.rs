//! Synchronous telemetry processing and stack correlation engine (`Pipeline`).
//!
//! # Role in the Architecture
//!
//! [`Pipeline`] wraps [`CallStackCorrelator`] and provides three ingestion entry points:
//! - [`Pipeline::feed_envelope`]: Primary zero-copy path driven by [`EventDispatcher`](super::EventDispatcher)
//!   for pre-decoded [`TelemetryEnvelope`] items emitted by [`PipelineEventRouter`](super::PipelineEventRouter).
//! - [`Pipeline::feed_raw`]: Direct zero-copy `&RawEvent` ingestion for single-threaded or inline consumers.
//! - [`Pipeline::feed`]: Owned `&EventRecord` ingestion for standalone unit tests.

use crate::pipeline::call_stack_correlator::CallStackCorrelator;
use crate::pipeline::constants::{NT_KERNEL_STACK_WALK_GUID, guid_matches, stack_walk_opcodes};
use crate::pipeline::etw_schemas::nt_kernel::stack_walk::StackWalkEvent;
use crate::pipeline::event::Event;
use crate::pipeline::router::TelemetryEnvelope;
use crate::sensors::etw::{EventRecord, RawEvent};

/// Synchronous telemetry correlation engine pairing trigger events with out-of-band kernel stack walks.
pub struct Pipeline {
    /// Stateful correlator matching `(EventTimeStamp, ProcessId, ThreadId)` tuples.
    correlator: CallStackCorrelator,
}

impl Default for Pipeline {
    fn default() -> Self {
        Self::new()
    }
}

impl Pipeline {
    /// Creates a new [`Pipeline`] with default [`CallStackCorrelator`] capacity and timeout settings.
    pub fn new() -> Self {
        Self {
            correlator: CallStackCorrelator::new(),
        }
    }

    /// Feeds a pre-decoded [`TelemetryEnvelope`] from [`PipelineEventRouter`](crate::pipeline::PipelineEventRouter)
    /// into the stack correlator without any `Vec<u8>` re-parsing.
    ///
    /// # Returns
    ///
    /// `Some(Event)` when an event does not require async stack correlation or has just been
    /// paired with its matching `StackWalkEvent`; `None` when buffered awaiting correlation.
    #[inline]
    pub fn feed_envelope(&mut self, envelope: TelemetryEnvelope) -> Option<Event> {
        match envelope {
            TelemetryEnvelope::StackWalk(sw) => self.correlator.process_stack_walk_event(sw),
            TelemetryEnvelope::Trigger {
                event,
                needs_async_stack,
            } => self.correlator.process_trigger(event, needs_async_stack),
        }
    }

    /// Decodes and feeds a borrowed zero-copy [`RawEvent`] directly into the pipeline.
    #[inline]
    pub fn feed_raw(&mut self, event: &RawEvent) -> Option<Event> {
        if guid_matches(event.provider_id(), &NT_KERNEL_STACK_WALK_GUID)
            && event.opcode() == stack_walk_opcodes::STACK_WALK
        {
            let sw = StackWalkEvent::try_from(event).ok()?;
            return self.correlator.process_stack_walk_event(sw);
        }

        let (domain_event, requires_async_stack) = Event::from_raw_event(event)?;
        self.correlator
            .process_trigger(domain_event, requires_async_stack)
    }

    /// Decodes and feeds an owned [`EventRecord`] into the pipeline.
    pub fn feed(&mut self, record: &EventRecord) -> Option<Event> {
        if guid_matches(&record.provider_id, &NT_KERNEL_STACK_WALK_GUID)
            && record.opcode == stack_walk_opcodes::STACK_WALK
        {
            return self.correlator.process_stack_walk(record);
        }

        let (event, requires_async_stack) = Event::from_record(record)?;
        let needs_async_stack = requires_async_stack && record.stack_trace.is_none();
        self.correlator.process_trigger(event, needs_async_stack)
    }

    /// Returns `true` if no events or orphan stack traces are currently buffered awaiting correlation.
    #[inline]
    pub fn is_correlator_empty(&self) -> bool {
        self.correlator.is_empty()
    }

    /// Flushes and returns any buffered trigger events that exceeded the stack-correlation timeout.
    pub fn flush_expired(&mut self) -> Vec<Event> {
        self.correlator.flush_expired()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::core::GUID;

    fn create_process_record(pid: u32, timestamp: i64) -> EventRecord {
        let mut user_data = Vec::new();
        user_data.extend_from_slice(&(0xAAAA_BBBBusize).to_ne_bytes()); // UniqueProcessKey
        user_data.extend_from_slice(&pid.to_ne_bytes()); // ProcessId
        user_data.extend_from_slice(&4u32.to_ne_bytes()); // ParentId
        user_data.extend_from_slice(&1u32.to_ne_bytes()); // SessionId
        user_data.extend_from_slice(&0i32.to_ne_bytes()); // ExitStatus
        user_data.extend_from_slice(&(0x200000usize).to_ne_bytes()); // DirectoryTableBase
        user_data.extend_from_slice(&[1u8, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0]); // SID S-1-5-18
        user_data.extend_from_slice(b"cmd.exe\0");
        let cmd: Vec<u8> = "cmd.exe\0"
            .encode_utf16()
            .flat_map(|u| u.to_ne_bytes())
            .collect();
        user_data.extend_from_slice(&cmd);

        EventRecord {
            provider_id: GUID {
                data1: 0x22fb2cd6,
                data2: 0x0e7b,
                data3: 0x4226,
                data4: [0xa0, 0x66, 0x61, 0x80, 0xf7, 0x71, 0x24, 0x65],
            },
            event_id: 0,
            version: 2,
            opcode: 1, // Start
            level: 0,
            process_id: pid,
            thread_id: 100,
            timestamp,
            user_data,
            stack_trace: None,
        }
    }

    fn create_syscall_record(pid: u32, timestamp: i64, syscall_addr: usize) -> EventRecord {
        EventRecord {
            provider_id: GUID {
                data1: 0xce1dbfb4,
                data2: 0x137e,
                data3: 0x4da6,
                data4: [0x87, 0xb0, 0x3f, 0x59, 0xaa, 0x10, 0x2c, 0xbc],
            },
            event_id: 0,
            version: 2,
            opcode: 51, // SysCallEnter
            level: 0,
            process_id: pid,
            thread_id: 100,
            timestamp,
            user_data: syscall_addr.to_ne_bytes().to_vec(),
            stack_trace: None,
        }
    }

    fn create_stack_walk_record(pid: u32, tid: u32, event_ts: u64, frames: &[u64]) -> EventRecord {
        let mut user_data = Vec::new();
        user_data.extend_from_slice(&event_ts.to_ne_bytes()); // EventTimeStamp
        user_data.extend_from_slice(&pid.to_ne_bytes()); // StackProcess
        user_data.extend_from_slice(&tid.to_ne_bytes()); // StackThread
        for frame in frames {
            user_data.extend_from_slice(&frame.to_ne_bytes());
        }

        EventRecord {
            provider_id: GUID {
                data1: 0xdef2fe46,
                data2: 0x7bd6,
                data3: 0x4b80,
                data4: [0xbd, 0x94, 0xf5, 0x7f, 0xe2, 0x0d, 0x0c, 0xe3],
            },
            event_id: 0,
            version: 2,
            opcode: 32, // StackWalk
            level: 0,
            process_id: pid,
            thread_id: tid,
            timestamp: 99_999,
            user_data,
            stack_trace: None,
        }
    }

    /// Verifies that process start records immediately produce ready Event::Process without buffering.
    #[test]
    fn test_pipeline_process_event_immediate_passthrough() {
        let mut pipeline = Pipeline::new();
        let record = create_process_record(1234, 1_000);

        let event = pipeline
            .feed(&record)
            .expect("Process event should be emitted immediately");
        match event {
            Event::Process(p) => {
                assert_eq!(p.process_id.0, 1234);
                assert_eq!(p.image_file_name, "cmd.exe");
            }
            _ => panic!("Expected Event::Process"),
        }
    }

    /// Verifies that syscall events are buffered until their matching StackWalk record arrives.
    #[test]
    fn test_pipeline_syscall_event_stack_correlation() {
        let mut pipeline = Pipeline::new();
        let syscall_record = create_syscall_record(4321, 5_000, 0x7FFF_1122_3344);

        // Syscall record requires async stack, so feeding returns None initially
        let pending = pipeline.feed(&syscall_record);
        assert!(
            pending.is_none(),
            "Syscall should be buffered awaiting StackWalk"
        );

        // Feed matching StackWalk record
        let stack_record = create_stack_walk_record(4321, 100, 5_000, &[0x7FFF_AAAA, 0x7FFF_BBBB]);
        let completed = pipeline
            .feed(&stack_record)
            .expect("Stack walk must complete pending syscall");

        match completed {
            Event::Syscall(s) => {
                assert_eq!(s.process_id.0, 4321);
                assert_eq!(s.syscall_address, 0x7FFF_1122_3344);
                assert_eq!(s.stack_trace.unwrap().frames(), &[0x7FFF_AAAA, 0x7FFF_BBBB]);
            }
            _ => panic!("Expected Event::Syscall"),
        }
    }
}
