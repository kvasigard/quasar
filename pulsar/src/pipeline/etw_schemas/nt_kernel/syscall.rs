//! Zero-copy MOF DTO definitions for Windows Kernel `PerfInfo` Syscall events (`SysCallEnter`).
//!
//! # Event Opcodes & MOF Classes (`PerfInfo` GUID `{ce1dbfb4-137e-4da6-87b0-3f59aa102cbc}`)
//!
//! | Opcode | Constant / Event Name       | Description                                        | MOF Class      |
//! |--------|-----------------------------|----------------------------------------------------|----------------|
//! | `51`   | `EVENT_TRACE_TYPE_SYSENTER` | System call entry (transition to kernel execution) | `SysCallEnter` |
//! | `52`   | `EVENT_TRACE_TYPE_SYSEXIT`  | System call exit (return to user mode)             | `SysCallExit`  |
//!
//! Reference: <https://learn.microsoft.com/en-us/windows/win32/etw/nt-kernel-logger-constants>

use thiserror::Error;

use crate::pipeline::etw_schemas::cursor::ByteCursor;
use crate::sensors::etw::RawEvent;

/// Error returned when a `SysCallEnter` (Opcode 51) payload contains fewer bytes than the event's pointer width.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum DtoSyscallError {
    /// The `UserData` slice had fewer than `expected` (`4` or `8`) bytes (`got`).
    #[error("Buffer too short for Syscall payload (expected {0} bytes, got {1})")]
    BufferTooShort(usize, usize),
}

/// Zero-copy DTO for `SysCallEnter` (Opcode 51) MOF payload.
///
/// Emitted by the kernel when `PERF_SYSCALL` is enabled and a thread transitions into ring 0
/// via `syscall` / `sysenter`. Contains the single pointer-sized virtual address of the
/// servicing SSDT routine in `ntoskrnl.exe` or `win32k.sys`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
#[allow(non_snake_case)]
pub struct SysCallEnter_TypeGroup1 {
    /// Virtual memory address of the kernel system call handler routine (e.g., `NtAllocateVirtualMemory`).
    ///
    /// Decoded via [`ByteCursor::read_ptr_usize`] (`8` bytes on 64-bit events, `4` bytes on 32-bit events).
    pub SysCallAddress: usize,
}

impl SysCallEnter_TypeGroup1 {
    /// Parses a `SysCallEnter` payload from a bitness-aware [`ByteCursor`].
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
