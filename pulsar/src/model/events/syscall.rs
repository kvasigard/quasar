//! Strongly-typed domain event for system call telemetry derived from the legacy NT Kernel Logger
//! ETW provider (`PerfInfo` group).
//!
//! Reference documentation:
//! <https://learn.microsoft.com/en-us/windows/win32/etw/nt-kernel-logger-constants>

use thiserror::Error;

use crate::model::types::{ProcessId, StackTrace};
use crate::pipeline::etw_schemas::nt_kernel::syscall::{DtoSyscallError, SysCallEnter_TypeGroup1};
use crate::sensors::etw::EventRecord;

/// Domain error encountered while parsing and validating Syscall telemetry events.
#[derive(Debug, Error)]
pub enum SyscallEventError {
    #[error("Unknown or unsupported ETW syscall opcode: {0}")]
    UnknownOpcode(u8),

    #[error("Syscall DTO parse error: {0}")]
    Dto(#[from] DtoSyscallError),
}

/// Strongly-typed domain event representing an invocation of a kernel system call.
///
/// Emitted when a user-mode thread executes a system call transition into the Windows kernel.
/// Security engines analyze the associated `stack_trace` and `syscall_address` to detect
/// Direct Syscalls, unbacked code execution, and shellcode loaders.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyscallEvent {
    /// Ingestion timestamp (QPC / FileTime).
    pub timestamp: i64,

    /// PID of the process executing the system call.
    pub process_id: ProcessId,

    /// TID of the specific thread executing the system call.
    pub thread_id: u32,

    /// Virtual memory address of the target kernel syscall handler function (e.g. `NtCreateFile`).
    pub syscall_address: usize,

    /// Associated call stack instruction pointer frames (if kernel stack walking is enabled).
    pub stack_trace: Option<StackTrace>,
}

impl SyscallEvent {
    /// Attaches or updates the correlated call stack trace for this system call.
    pub fn with_stack_trace(mut self, stack_trace: StackTrace) -> Self {
        self.stack_trace = Some(stack_trace);
        self
    }

    /// Mutably attaches a correlated call stack trace to this system call.
    pub fn attach_stack_trace(&mut self, stack_trace: StackTrace) {
        self.stack_trace = Some(stack_trace);
    }
}

impl TryFrom<&EventRecord> for SyscallEvent {
    type Error = SyscallEventError;

    /// Validates the opcode and transforms the raw `EventRecord` into a strongly-typed `SyscallEvent`.
    fn try_from(record: &EventRecord) -> Result<Self, Self::Error> {
        // Opcode 51: SysCallEnter
        if record.opcode != 51 {
            return Err(SyscallEventError::UnknownOpcode(record.opcode));
        }

        // Deserialize zero-copy SysCallEnter DTO
        let dto = SysCallEnter_TypeGroup1::try_from(record.user_data.as_slice())?;

        Ok(Self {
            timestamp: record.timestamp,
            process_id: ProcessId(record.process_id),
            thread_id: record.thread_id,
            syscall_address: dto.SysCallAddress,
            stack_trace: record.stack_trace.clone().map(StackTrace::new),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::core::GUID;

    /// Verifies extraction of target kernel function addresses from Opcode 51 records and validates rejection of non-SysCallEnter opcodes.
    /// Mandatory for direct syscall anomaly detectors to guarantee only valid transition entry events are ingested.
    #[test]
    fn test_syscall_event_construction_and_opcode_filter() {
        let syscall_target: usize = 0x7FFF_1234_5678;
        let mut record = EventRecord {
            provider_id: GUID { data1: 0xce1dbfb4, data2: 0x137e, data3: 0x4da6, data4: [0x87, 0xb0, 0x3f, 0x59, 0xaa, 0x10, 0x2c, 0xbc] },
            event_id: 0,
            version: 2,
            opcode: 51, // SysCallEnter
            level: 0,
            process_id: 8888,
            thread_id: 9999,
            timestamp: 12345,
            user_data: syscall_target.to_ne_bytes().to_vec(),
            stack_trace: Some(vec![0x7FFF_AAAA, 0x7FFF_BBBB]),
        };

        let event = SyscallEvent::try_from(&record).expect("Opcode 51 must produce SyscallEvent");
        assert_eq!(event.syscall_address, syscall_target);
        assert_eq!(event.process_id, ProcessId(8888));
        assert_eq!(event.stack_trace.unwrap().frames(), &[0x7FFF_AAAA, 0x7FFF_BBBB]);

        // Wrong opcode (e.g. SysCallExit 52)
        record.opcode = 52;
        assert!(matches!(
            SyscallEvent::try_from(&record),
            Err(SyscallEventError::UnknownOpcode(52))
        ));
    }
}


