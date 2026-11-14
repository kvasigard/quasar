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

use thiserror::Error;

use crate::pipeline::etw_schemas::cursor::ByteCursor;
use crate::sensors::etw::RawEvent;

/// Error type encountered while parsing Syscall ETW DTO structures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
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

impl SysCallEnter_TypeGroup1 {
    /// Parses `SysCallEnter` from a bitness-aware [`ByteCursor`].
    #[inline(always)]
    pub fn parse(cursor: &mut ByteCursor<'_>) -> Result<Self, DtoSyscallError> {
        let ptr_size = cursor.pointer_size();
        let rem = cursor.remaining();
        if rem < ptr_size {
            return Err(DtoSyscallError::BufferTooShort(ptr_size, rem));
        }

        let addr = cursor
            .read_ptr_usize("SysCallAddress")
            .map_err(|_| DtoSyscallError::BufferTooShort(ptr_size, rem))?;

        Ok(Self {
            SysCallAddress: addr,
        })
    }
}

impl<'a> TryFrom<&'a [u8]> for SysCallEnter_TypeGroup1 {
    type Error = DtoSyscallError;

    #[inline(always)]
    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        Self::parse(&mut ByteCursor::new(bytes))
    }
}

impl TryFrom<&RawEvent> for SysCallEnter_TypeGroup1 {
    type Error = DtoSyscallError;

    #[inline(always)]
    fn try_from(event: &RawEvent) -> Result<Self, Self::Error> {
        Self::parse(&mut ByteCursor::from_raw_event(event))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::size_of;

    /// Verifies zero-copy extraction of the kernel syscall entry address and validates rejection of undersized buffers.
    /// Critical for direct syscall detection engines to avoid processing corrupt instruction addresses that trigger false alerts.
    #[test]
    fn test_syscall_enter_dto_deserialization_and_bounds() {
        let target_addr: usize = 0x7FFF_8899_AABB_CCDD;
        let bytes = target_addr.to_ne_bytes();

        let dto =
            SysCallEnter_TypeGroup1::try_from(&bytes[..]).expect("Should deserialize pointer");
        assert_eq!(dto.SysCallAddress, target_addr);

        let truncated = &bytes[..size_of::<usize>() - 1];
        assert!(matches!(
            SysCallEnter_TypeGroup1::try_from(truncated),
            Err(DtoSyscallError::BufferTooShort(_, _))
        ));
    }

    #[test]
    fn test_syscall_enter_32bit_pointer_deserialization() {
        let bytes = 0x8050_1234u32.to_ne_bytes();
        let mut cursor = ByteCursor::with_pointer_size(&bytes, 4);
        let dto = SysCallEnter_TypeGroup1::parse(&mut cursor).expect("32-bit syscall must parse");
        assert_eq!(dto.SysCallAddress, 0x8050_1234);
    }
}
