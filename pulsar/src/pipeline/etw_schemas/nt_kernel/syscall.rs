//! DTO definitions for ETW NT Kernel Logger Syscall events.
//!
//! Event types for ETW Kernel Syscall tracing (`PerfInfo` provider GUID `{CE1DBFB4-39EA-4851-89E0-A77CBFCCE4ED}`):
//!
//! +-------+---------------------------------+----------------------------------------------------+-----------------------+
//! | Value | Constant / Event Name           | Description                                        | MOF Class             |
//! +-------+---------------------------------+----------------------------------------------------+-----------------------+
//! | 51    | EVENT_TRACE_TYPE_SYSENTER       | System call entry (transition to kernel execution) | SysCallEnter          |
//! | 52    | EVENT_TRACE_TYPE_SYSEXIT        | System call exit (return to user mode)             | SysCallExit           |
//! +-------+---------------------------------+----------------------------------------------------+-----------------------+
//!
//! Reference documentation:
//! <https://learn.microsoft.com/en-us/windows/win32/etw/nt-kernel-logger-constants>

use std::mem::size_of;
use thiserror::Error;

/// Error type encountered while parsing Syscall ETW DTO structures.
#[derive(Debug, Error)]
pub enum DtoSyscallError {
    #[error("Buffer too short for Syscall payload (expected {0} bytes, got {1})")]
    BufferTooShort(usize, usize),
}

/// Raw zero-copy DTO for `SysCallEnter` (Opcode 51) event payload.
///
/// Captured immediately when a thread executes a system call transition into the kernel.
/// The payload contains the entry point pointer of the servicing system call function in `ntoskrnl.exe` / `win32k.sys`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
#[allow(non_snake_case)]
pub struct SysCallEnter_TypeGroup1 {
    /// Virtual memory address of the kernel system call handler routine (e.g. `NtCreateFile`, `NtAllocateVirtualMemory`).
    /// In 64-bit Windows, this is an 8-byte pointer; in 32-bit Windows, it is a 4-byte pointer.
    pub SysCallAddress: usize,
}

impl<'a> TryFrom<&'a [u8]> for SysCallEnter_TypeGroup1 {
    type Error = DtoSyscallError;

    /// Validates buffer boundaries and reads the pointer-sized `SysCallAddress` without copying.
    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        const PTR_SIZE: usize = size_of::<usize>();

        if bytes.len() < PTR_SIZE {
            return Err(DtoSyscallError::BufferTooShort(PTR_SIZE, bytes.len()));
        }

        let address_bytes = bytes[..PTR_SIZE]
            .try_into()
            .map_err(|_| DtoSyscallError::BufferTooShort(PTR_SIZE, bytes.len()))?;

        Ok(Self {
            SysCallAddress: usize::from_ne_bytes(address_bytes),
        })
    }
}

