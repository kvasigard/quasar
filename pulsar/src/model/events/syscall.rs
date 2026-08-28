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

