//! Unified pipeline event definitions, zero-copy decoding, and metadata accessors.
//!
//! [`Event`] is the normalized domain sum type flowing from [`PipelineEventRouter`](super::PipelineEventRouter)
//! and [`DriverSensor`](crate::sensors::driver::DriverSensor) into [`EventDispatcher`](super::EventDispatcher)
//! and all registered [`EventListener`](super::EventListener) sinks.

use shared::ring_buffer::LsassAccessEvent;

use crate::model::events::{ProcessEvent, SyscallEvent};
use crate::model::types::StackTrace;
use crate::pipeline::constants::*;
use crate::sensors::etw::{EventRecord, RawEvent};

/// Normalized domain event flowing through the Pulsar analytics pipeline.
///
/// Each variant represents a distinct security telemetry class originating either from
/// Windows ETW ([`Event::Process`], [`Event::Syscall`]) or from the Singularity kernel
/// driver's per-CPU ring buffer ([`Event::LsassAccess`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// Process creation, termination, or rundown snapshot event (`PERF_PROCESS`).
    Process(ProcessEvent),

    /// Kernel system call entry event (`PERF_SYSCALL` / `SysCallEnter`, Opcode 51).
    Syscall(SyscallEvent),

    /// Pre-operation handle creation or duplication targeting `lsass.exe` intercepted by
    /// the Singularity kernel driver (`ObRegisterCallbacks`).
    LsassAccess(LsassAccessEvent),
}

impl Event {
    /// Returns the raw timestamp (QPC ticks) of this domain event, or `0` for driver events
    /// that do not carry an ETW header timestamp.
    pub fn timestamp(&self) -> i64 {
        match self {
            Event::Process(e) => e.timestamp,
            Event::Syscall(e) => e.timestamp,
            Event::LsassAccess(_) => 0,
        }
    }

    /// Returns the OS Process ID (PID) that emitted or initiated this event.
    pub fn process_id(&self) -> u32 {
        match self {
            Event::Process(e) => e.emitter_pid.0,
            Event::Syscall(e) => e.process_id.0,
            Event::LsassAccess(e) => e.source_pid,
        }
    }

    /// Returns the OS Thread ID (TID) that emitted or initiated this event.
    pub fn thread_id(&self) -> u32 {
        match self {
            Event::Process(e) => e.emitter_tid,
            Event::Syscall(e) => e.thread_id,
            Event::LsassAccess(_) => 0,
        }
    }

    /// Attaches a correlated [`StackTrace`] to this domain event.
    pub fn attach_stack_trace(&mut self, stack_trace: StackTrace) {
        match self {
            Event::Process(e) => e.stack_trace = Some(stack_trace),
            Event::Syscall(e) => e.stack_trace = Some(stack_trace),
            Event::LsassAccess(_) => {}
        }
    }

    /// Decodes a borrowed [`RawEvent`] directly into a domain [`Event`] with zero intermediate
    /// `Vec<u8>` allocation.
    ///
    /// # Returns
    ///
    /// `Some((event, requires_async_stack))` if the event's provider GUID, opcode, and payload
    /// schema are valid; `None` otherwise.
    pub fn from_raw_event(event: &RawEvent) -> Option<(Self, bool)> {
        let provider_id = event.provider_id();
        let opcode = event.opcode();

        let is_process_provider = guid_matches(provider_id, &NT_KERNEL_PROCESS_GUID)
            || guid_matches(provider_id, &MANIFEST_KERNEL_PROCESS_GUID);

        if is_process_provider {
            return match opcode {
                process_opcodes::START
                | process_opcodes::END
                | process_opcodes::DC_START
                | process_opcodes::DC_END
                | process_opcodes::DEFUNCT => ProcessEvent::try_from(event)
                    .ok()
                    .map(|e| (Event::Process(e), false)),
                _ => None,
            };
        }

        if (guid_matches(provider_id, &NT_KERNEL_PERFINFO_GUID)
            || provider_id.data1 == NT_KERNEL_PERFINFO_PROVIDER_GUID_DATA1)
            && opcode == syscall_opcodes::SYSCALL_ENTER
        {
            return SyscallEvent::try_from(event).ok().map(|e| {
                let needs_async = e.stack_trace.is_none();
                (Event::Syscall(e), needs_async)
            });
        }

        None
    }

    /// Decodes an owned [`EventRecord`] into a domain [`Event`] and indicates whether the
    /// event requires asynchronous kernel `StackWalk` correlation.
    pub fn from_record(record: &EventRecord) -> Option<(Self, bool)> {
        let is_process_provider = guid_matches(&record.provider_id, &NT_KERNEL_PROCESS_GUID)
            || guid_matches(&record.provider_id, &MANIFEST_KERNEL_PROCESS_GUID);

        if is_process_provider {
            return match record.opcode {
                process_opcodes::START
                | process_opcodes::END
                | process_opcodes::DC_START
                | process_opcodes::DC_END
                | process_opcodes::DEFUNCT => ProcessEvent::try_from(record)
                    .ok()
                    .map(|e| (Event::Process(e), false)),
                _ => None,
            };
        }

        if (guid_matches(&record.provider_id, &NT_KERNEL_PERFINFO_GUID)
            || record.provider_id.data1 == NT_KERNEL_PERFINFO_PROVIDER_GUID_DATA1)
            && record.opcode == syscall_opcodes::SYSCALL_ENTER
        {
            return SyscallEvent::try_from(record)
                .ok()
                .map(|e| (Event::Syscall(e), true));
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classic_nt_kernel_process_guid_decoding() {
        let ptr_size = std::mem::size_of::<usize>();
        let mut user_data = Vec::new();
        user_data.extend_from_slice(&vec![0x11u8; ptr_size]); // UniqueProcessKey
        user_data.extend_from_slice(&1234u32.to_ne_bytes()); // ProcessId
        user_data.extend_from_slice(&4u32.to_ne_bytes()); // ParentId
        user_data.extend_from_slice(&0u32.to_ne_bytes()); // SessionId
        user_data.extend_from_slice(&0i32.to_ne_bytes()); // ExitStatus
        user_data.extend_from_slice(&vec![0x22u8; ptr_size]); // DirectoryTableBase
        user_data.extend_from_slice(&[1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0]); // SID
        user_data.extend_from_slice(b"explorer.exe\0"); // Even length (12 chars + 1 null = 13 bytes -> odd offset!)
        for ch in "C:\\Windows\\explorer.exe".encode_utf16() {
            user_data.extend_from_slice(&ch.to_le_bytes());
        }
        user_data.extend_from_slice(&0u16.to_le_bytes());

        let record = EventRecord {
            provider_id: NT_KERNEL_PROCESS_GUID,
            event_id: 0,
            opcode: process_opcodes::START,
            version: 2,
            level: 0,
            process_id: 4,
            thread_id: 8,
            timestamp: 100_000,
            user_data,
            stack_trace: None,
        };

        let (event, requires_stack) =
            Event::from_record(&record).expect("Classic NT Kernel Process GUID must decode");
        assert!(!requires_stack);
        match event {
            Event::Process(proc_ev) => {
                assert_eq!(proc_ev.process_id.0, 1234);
                assert_eq!(proc_ev.image_file_name, "explorer.exe");
                assert_eq!(proc_ev.command_line, "C:\\Windows\\explorer.exe");
            }
            other => panic!("Expected Event::Process, got {other:?}"),
        }
    }
}
