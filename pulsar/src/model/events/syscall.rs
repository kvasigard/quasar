//! Strongly-typed domain event for system call telemetry derived from the NT Kernel Logger
//! ETW provider (`PerfInfo` group).
//!
//! Reference documentation:
//! <https://learn.microsoft.com/en-us/windows/win32/etw/nt-kernel-logger-constants>

use thiserror::Error;

use crate::model::types::{ProcessId, StackTrace};
use crate::pipeline::etw_schemas::nt_kernel::syscall::{DtoSyscallError, SysCallEnter_TypeGroup1};
use crate::sensors::etw::{EventRecord, RawEvent};

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

impl TryFrom<&RawEvent> for SyscallEvent {
    type Error = SyscallEventError;

    #[inline]
    fn try_from(event: &RawEvent) -> Result<Self, Self::Error> {
        if event.opcode() != 51 {
            return Err(SyscallEventError::UnknownOpcode(event.opcode()));
        }

        let dto = SysCallEnter_TypeGroup1::try_from(event)?;

        Ok(Self {
            timestamp: event.timestamp(),
            process_id: ProcessId(event.process_id()),
            thread_id: event.thread_id(),
            syscall_address: dto.SysCallAddress,
            stack_trace: event.extract_call_stack().map(StackTrace::new),
        })
    }
}

impl TryFrom<&EventRecord> for SyscallEvent {
    type Error = SyscallEventError;

    #[inline]
    fn try_from(record: &EventRecord) -> Result<Self, Self::Error> {
        if record.opcode != 51 {
            return Err(SyscallEventError::UnknownOpcode(record.opcode));
        }

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
    use crate::sensors::etw::SyntheticEvent;
    use windows_sys::core::GUID;

    /// Verifies extraction of target kernel function addresses from Opcode 51 records and validates rejection of non-SysCallEnter opcodes.
    #[test]
    fn test_syscall_event_construction_and_opcode_filter() {
        let syscall_target: usize = 0x7FFF_1234_5678;
        let guid = GUID {
            data1: 0xce1dbfb4,
            data2: 0x137e,
            data3: 0x4da6,
            data4: [0x87, 0xb0, 0x3f, 0x59, 0xaa, 0x10, 0x2c, 0xbc],
        };

        let syn = SyntheticEvent::new(
            guid,
            2,
            51,
            8888,
            9999,
            12345,
            syscall_target.to_ne_bytes().to_vec(),
        )
        .with_inline_stack64(&[0x7FFF_AAAA, 0x7FFF_BBBB]);

        let event = SyscallEvent::try_from(syn.as_raw_event()).expect("Opcode 51 must parse");
        assert_eq!(event.syscall_address, syscall_target);
        assert_eq!(event.process_id, ProcessId(8888));
        assert_eq!(
            event.stack_trace.unwrap().frames(),
            &[0x7FFF_AAAA, 0x7FFF_BBBB]
        );

        let syn_wrong = SyntheticEvent::new(
            guid,
            2,
            52,
            8888,
            9999,
            12345,
            syscall_target.to_ne_bytes().to_vec(),
        );
        assert!(matches!(
            SyscallEvent::try_from(syn_wrong.as_raw_event()),
            Err(SyscallEventError::UnknownOpcode(52))
        ));
    }
}
