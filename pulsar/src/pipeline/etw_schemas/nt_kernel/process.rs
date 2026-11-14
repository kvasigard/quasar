//! Zero-copy MOF DTO schemas for Windows Kernel `Process` events (`Process_V0..V4`).
//!
//! # Event Opcodes & MOF Classes
//!
//! | Opcode | Constant / Event Name            | Description                                         | MOF Class               |
//! |--------|----------------------------------|-----------------------------------------------------|-------------------------|
//! | `1`    | `EVENT_TRACE_TYPE_START`         | Process creation event                              | `Process_V*_TypeGroup1` |
//! | `2`    | `EVENT_TRACE_TYPE_END`           | Process termination event                           | `Process_V*_TypeGroup1` |
//! | `3`    | `EVENT_TRACE_TYPE_DC_START`      | Rundown of processes active at trace start          | `Process_V*_TypeGroup1` |
//! | `4`    | `EVENT_TRACE_TYPE_DC_END`        | Rundown of processes active at trace stop           | `Process_V*_TypeGroup1` |
//! | `32`   | Performance Counters             | Process resource utilization counters               | `Process_V2_TypeGroup2` |
//! | `33`   | Performance Counters Rundown     | Rundown of performance counters at session stop     | `Process_V2_TypeGroup2` |
//! | `39`   | Defunct Process                  | Zombie process whose `EPROCESS` object still exists | `Process_V*_TypeGroup1` |
//!
//! # Header PID vs. Payload PID
//!
//! Process creation (`Start`) and rundown (`DCStart`) events are frequently logged in the thread
//! context of the parent process or the `System` kernel process (`PID 4`). Consequently,
//! `EVENT_HEADER.ProcessId` represents the *creator/emitter* PID, whereas the actual target
//! process's `ProcessId` and `ParentId` are embedded inside the `UserData` payload decoded by
//! these DTOs.
//!
//! Reference: <https://learn.microsoft.com/en-us/windows/win32/etw/process-v2>

use crate::helpers::strings::StringError;
use crate::pipeline::etw_schemas::cursor::{ByteCursor, CursorError};
use crate::sensors::etw::RawEvent;
use thiserror::Error;

/// Errors encountered while decoding a kernel `Process` MOF payload into a DTO.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum DtoProcessError {
    /// The `UserData` buffer ended before the named field could be read.
    #[error("Buffer too short for field '{0}'")]
    BufferTooShort(&'static str),

    /// The binary `UserSID` field had an invalid revision or truncated sub-authorities.
    #[error("Invalid binary SID in field '{0}'")]
    InvalidSid(&'static str),

    /// Either `ImageFileName` (ANSI) or `CommandLine` (UTF-16LE) lacked a null terminator or had invalid encoding.
    #[error("String parsing error in field '{0}': {1}")]
    String(&'static str, #[source] StringError),
}

impl From<CursorError> for DtoProcessError {
    #[inline]
    fn from(err: CursorError) -> Self {
        match err {
            CursorError::BufferTooShort { field, .. } => Self::BufferTooShort(field),
            CursorError::InvalidSid(field) => Self::InvalidSid(field),
            CursorError::String(field, source) => Self::String(field, source),
            CursorError::UnalignedTrailingBytes { field, .. } => Self::BufferTooShort(field),
        }
    }
}

/// Version 0 `Process` MOF schema (`Process_V0_TypeGroup1`, Windows XP / Server 2003).
#[allow(nonstandard_style)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Process_V0_TypeGroup1<'a> {
    /// Target Process ID.
    pub ProcessId: u32,
    /// Parent Process ID.
    pub ParentId: u32,
    /// Borrowed binary Security Identifier (`SID`) of the process token.
    pub UserSID: &'a [u8],
    /// Null-terminated ANSI image file name (e.g., `"cmd.exe"`).
    pub ImageFileName: &'a str,
}

impl<'a> Process_V0_TypeGroup1<'a> {
    /// Parses a Version 0 process payload from a bitness-aware [`ByteCursor`].
    #[inline]
    pub fn parse(cursor: &mut ByteCursor<'a>) -> Result<Self, DtoProcessError> {
        cursor.ensure_remaining(8, "FixedHeader")?;
        Ok(Self {
            ProcessId: cursor.read_u32("ProcessId")?,
            ParentId: cursor.read_u32("ParentId")?,
            UserSID: cursor.read_sid("UserSID")?,
            ImageFileName: cursor.read_ansi_str("ImageFileName")?,
        })
    }
}

impl<'a> TryFrom<&'a [u8]> for Process_V0_TypeGroup1<'a> {
    type Error = DtoProcessError;

    #[inline]
    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        Self::parse(&mut ByteCursor::new(bytes))
    }
}

impl<'a> TryFrom<&'a RawEvent> for Process_V0_TypeGroup1<'a> {
    type Error = DtoProcessError;

    #[inline]
    fn try_from(event: &'a RawEvent) -> Result<Self, Self::Error> {
        Self::parse(&mut ByteCursor::from_raw_event(event))
    }
}

/// Version 1 `Process` MOF schema (`Process_V1_TypeGroup1`, Windows Vista / 7 / Server 2008).
#[allow(nonstandard_style)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Process_V1_TypeGroup1<'a> {
    /// Physical address of the process page directory (`CR3`).
    pub PageDirectoryBase: usize,
    /// Target Process ID.
    pub ProcessId: u32,
    /// Parent Process ID.
    pub ParentId: u32,
    /// Terminal Services session ID.
    pub SessionId: u32,
    /// Process exit code (meaningful on `End` / `Defunct` opcodes).
    pub ExitStatus: i32,
    /// Borrowed binary Security Identifier (`SID`) of the process token.
    pub UserSID: &'a [u8],
    /// Null-terminated ANSI short image file name.
    pub ImageFileName: &'a str,
}

impl<'a> Process_V1_TypeGroup1<'a> {
    /// Parses a Version 1 process payload from a bitness-aware [`ByteCursor`].
    #[inline]
    pub fn parse(cursor: &mut ByteCursor<'a>) -> Result<Self, DtoProcessError> {
        let fixed_size = cursor.pointer_size() + 16;
        cursor.ensure_remaining(fixed_size, "FixedHeader")?;

        Ok(Self {
            PageDirectoryBase: cursor.read_ptr_usize("PageDirectoryBase")?,
            ProcessId: cursor.read_u32("ProcessId")?,
            ParentId: cursor.read_u32("ParentId")?,
            SessionId: cursor.read_u32("SessionId")?,
            ExitStatus: cursor.read_i32("ExitStatus")?,
            UserSID: cursor.read_sid("UserSID")?,
            ImageFileName: cursor.read_ansi_str("ImageFileName")?,
        })
    }
}

impl<'a> TryFrom<&'a [u8]> for Process_V1_TypeGroup1<'a> {
    type Error = DtoProcessError;

    #[inline]
    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        Self::parse(&mut ByteCursor::new(bytes))
    }
}

impl<'a> TryFrom<&'a RawEvent> for Process_V1_TypeGroup1<'a> {
    type Error = DtoProcessError;

    #[inline]
    fn try_from(event: &'a RawEvent) -> Result<Self, Self::Error> {
        Self::parse(&mut ByteCursor::from_raw_event(event))
    }
}

/// Version 2 `Process` MOF schema (`Process_V2_TypeGroup1`, Windows 8 / Server 2012).
#[allow(nonstandard_style)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Process_V2_TypeGroup1<'a> {
    /// Kernel address of the `_EPROCESS` structure (`UniqueProcessKey`).
    pub UniqueProcessKey: usize,
    /// Target Process ID.
    pub ProcessId: u32,
    /// Parent Process ID.
    pub ParentId: u32,
    /// Terminal Services session ID.
    pub SessionId: u32,
    /// Process exit status code.
    pub ExitStatus: i32,
    /// Physical address of the process page directory table (`CR3`).
    pub DirectoryTableBase: usize,
    /// Borrowed binary Security Identifier (`SID`) of the process token.
    pub UserSID: &'a [u8],
    /// Null-terminated ANSI image file name (e.g., `"svchost.exe"`).
    pub ImageFileName: &'a str,
    /// Borrowed UTF-16LE byte slice (excluding the 2-byte NUL terminator) of the process command line.
    pub CommandLine: &'a [u8],
}

impl<'a> Process_V2_TypeGroup1<'a> {
    /// Parses a Version 2 process payload from a bitness-aware [`ByteCursor`].
    #[inline]
    pub fn parse(cursor: &mut ByteCursor<'a>) -> Result<Self, DtoProcessError> {
        let ptr_size = cursor.pointer_size();
        let fixed_size = ptr_size + 16 + ptr_size;
        cursor.ensure_remaining(fixed_size, "FixedHeader")?;

        Ok(Self {
            UniqueProcessKey: cursor.read_ptr_usize("UniqueProcessKey")?,
            ProcessId: cursor.read_u32("ProcessId")?,
            ParentId: cursor.read_u32("ParentId")?,
            SessionId: cursor.read_u32("SessionId")?,
            ExitStatus: cursor.read_i32("ExitStatus")?,
            DirectoryTableBase: cursor.read_ptr_usize("DirectoryTableBase")?,
            UserSID: cursor.read_sid("UserSID")?,
            ImageFileName: cursor.read_ansi_str("ImageFileName")?,
            CommandLine: cursor.read_utf16_bytes("CommandLine")?,
        })
    }
}

impl<'a> TryFrom<&'a [u8]> for Process_V2_TypeGroup1<'a> {
    type Error = DtoProcessError;

    #[inline]
    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        Self::parse(&mut ByteCursor::new(bytes))
    }
}

impl<'a> TryFrom<&'a RawEvent> for Process_V2_TypeGroup1<'a> {
    type Error = DtoProcessError;

    #[inline]
    fn try_from(event: &'a RawEvent) -> Result<Self, Self::Error> {
        Self::parse(&mut ByteCursor::from_raw_event(event))
    }
}

/// Version 3 and Version 4+ `Process` MOF schema (`Process_V3_TypeGroup1` / `Process_V4_TypeGroup1`,
/// Windows 8.1 / 10 / 11 / Server 2012 R2+).
///
/// Compared to Version 2, Version 3 inserts `Flags: u32` immediately after `DirectoryTableBase`
/// (and Version 4 appends `PackageFullName` and `ApplicationId` after `CommandLine`).
#[allow(nonstandard_style)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Process_V3_TypeGroup1<'a> {
    /// Kernel address of the `_EPROCESS` structure (`UniqueProcessKey`).
    pub UniqueProcessKey: usize,
    /// Target Process ID.
    pub ProcessId: u32,
    /// Parent Process ID.
    pub ParentId: u32,
    /// Terminal Services session ID.
    pub SessionId: u32,
    /// Process exit status code.
    pub ExitStatus: i32,
    /// Physical address of the process page directory table (`CR3`).
    pub DirectoryTableBase: usize,
    /// Process creation/rundown flags (`Flags`, added in schema V3).
    pub Flags: u32,
    /// Borrowed binary Security Identifier (`SID`) of the process token.
    pub UserSID: &'a [u8],
    /// Null-terminated ANSI image file name.
    pub ImageFileName: &'a str,
    /// Borrowed UTF-16LE byte slice (excluding the 2-byte NUL terminator) of the process command line.
    pub CommandLine: &'a [u8],
}

impl<'a> Process_V3_TypeGroup1<'a> {
    /// Parses a Version 3 or Version 4+ process payload from a bitness-aware [`ByteCursor`].
    #[inline]
    pub fn parse(cursor: &mut ByteCursor<'a>) -> Result<Self, DtoProcessError> {
        let ptr_size = cursor.pointer_size();
        let fixed_size = ptr_size + 16 + ptr_size + 4;
        cursor.ensure_remaining(fixed_size, "FixedHeader")?;

        Ok(Self {
            UniqueProcessKey: cursor.read_ptr_usize("UniqueProcessKey")?,
            ProcessId: cursor.read_u32("ProcessId")?,
            ParentId: cursor.read_u32("ParentId")?,
            SessionId: cursor.read_u32("SessionId")?,
            ExitStatus: cursor.read_i32("ExitStatus")?,
            DirectoryTableBase: cursor.read_ptr_usize("DirectoryTableBase")?,
            Flags: cursor.read_u32("Flags")?,
            UserSID: cursor.read_sid("UserSID")?,
            ImageFileName: cursor.read_ansi_str("ImageFileName")?,
            CommandLine: cursor.read_utf16_bytes("CommandLine")?,
        })
    }
}

impl<'a> TryFrom<&'a [u8]> for Process_V3_TypeGroup1<'a> {
    type Error = DtoProcessError;

    #[inline]
    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        Self::parse(&mut ByteCursor::new(bytes))
    }
}

impl<'a> TryFrom<&'a RawEvent> for Process_V3_TypeGroup1<'a> {
    type Error = DtoProcessError;

    #[inline]
    fn try_from(event: &'a RawEvent) -> Result<Self, Self::Error> {
        Self::parse(&mut ByteCursor::from_raw_event(event))
    }
}

/// Version 2 Process Performance Counters MOF schema (`Process_V2_TypeGroup2`, Opcodes 32 and 33).
#[allow(nonstandard_style)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Process_V2_TypeGroup2 {
    /// Kernel address of the `_EPROCESS` structure.
    pub UniqueProcessKey: usize,
    /// Target Process ID.
    pub ProcessId: u32,
    /// Cumulative user-mode CPU time.
    pub UserTime: u64,
    /// Cumulative kernel-mode CPU time.
    pub KernelTime: u64,
    /// Peak virtual address space size in bytes.
    pub PeakVirtualSize: usize,
    /// Peak working set size in bytes.
    pub PeakWorkingSetSize: usize,
    /// Current virtual address space size in bytes.
    pub VirtualSize: usize,
    /// Current pagefile usage in bytes.
    pub PagefileUsage: usize,
    /// Peak pagefile usage in bytes.
    pub PeakPagefileUsage: usize,
    /// Current working set size in bytes.
    pub WorkingSetSize: usize,
    /// Total soft + hard page fault count.
    pub PageFaultCount: u32,
    /// Total hard page fault count.
    pub HardFaultCount: u32,
    /// Current private commit charge.
    pub CommitCharge: usize,
    /// Peak private commit charge.
    pub PeakCommitCharge: usize,
    /// Total I/O read operations.
    pub ReadOperationCount: u64,
    /// Total I/O write operations.
    pub WriteOperationCount: u64,
    /// Total non-read/write I/O operations.
    pub OtherOperationCount: u64,
    /// Total bytes read.
    pub ReadTransferCount: u64,
    /// Total bytes written.
    pub WriteTransferCount: u64,
    /// Total bytes transferred in other I/O operations.
    pub OtherTransferCount: u64,
}

impl Process_V2_TypeGroup2 {
    /// Parses a V2 process performance counters payload from a bitness-aware [`ByteCursor`].
    #[inline]
    pub fn parse(cursor: &mut ByteCursor<'_>) -> Result<Self, DtoProcessError> {
        let total_size = (9 * cursor.pointer_size()) + 12 + 64;
        cursor.ensure_remaining(total_size, "FixedHeader")?;

        Ok(Self {
            UniqueProcessKey: cursor.read_ptr_usize("UniqueProcessKey")?,
            ProcessId: cursor.read_u32("ProcessId")?,
            UserTime: cursor.read_u64("UserTime")?,
            KernelTime: cursor.read_u64("KernelTime")?,
            PeakVirtualSize: cursor.read_ptr_usize("PeakVirtualSize")?,
            PeakWorkingSetSize: cursor.read_ptr_usize("PeakWorkingSetSize")?,
            VirtualSize: cursor.read_ptr_usize("VirtualSize")?,
            PagefileUsage: cursor.read_ptr_usize("PagefileUsage")?,
            PeakPagefileUsage: cursor.read_ptr_usize("PeakPagefileUsage")?,
            WorkingSetSize: cursor.read_ptr_usize("WorkingSetSize")?,
            PageFaultCount: cursor.read_u32("PageFaultCount")?,
            HardFaultCount: cursor.read_u32("HardFaultCount")?,
            CommitCharge: cursor.read_ptr_usize("CommitCharge")?,
            PeakCommitCharge: cursor.read_ptr_usize("PeakCommitCharge")?,
            ReadOperationCount: cursor.read_u64("ReadOperationCount")?,
            WriteOperationCount: cursor.read_u64("WriteOperationCount")?,
            OtherOperationCount: cursor.read_u64("OtherOperationCount")?,
            ReadTransferCount: cursor.read_u64("ReadTransferCount")?,
            WriteTransferCount: cursor.read_u64("WriteTransferCount")?,
            OtherTransferCount: cursor.read_u64("OtherTransferCount")?,
        })
    }
}

impl TryFrom<&[u8]> for Process_V2_TypeGroup2 {
    type Error = DtoProcessError;

    #[inline]
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Self::parse(&mut ByteCursor::new(bytes))
    }
}

impl TryFrom<&RawEvent> for Process_V2_TypeGroup2 {
    type Error = DtoProcessError;

    #[inline]
    fn try_from(event: &RawEvent) -> Result<Self, Self::Error> {
        Self::parse(&mut ByteCursor::from_raw_event(event))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verifies binary SID header parsing and ensures buffers shorter than the sub-authority declaration are rejected.
    /// Necessary because ETW passes raw binary token data where malformed lengths could trigger out-of-bounds slice indexing.
    #[test]
    fn test_parse_sid_boundaries_and_truncation() {
        // S-1-5-18 (Revision 1, 1 Sub-Authority, Authority 5, RID 18): 8 + 4 = 12 bytes
        let valid_sid = [1u8, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
        let mut cursor = ByteCursor::new(&valid_sid);
        let sid_slice = cursor.read_sid("UserSID").expect("Valid SID must parse");
        assert_eq!(sid_slice, &valid_sid);
        assert_eq!(cursor.position(), 12);

        // Header claims 2 sub-authorities (requires 16 bytes), but only 12 bytes provided
        let truncated_sid = [1u8, 2, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
        let mut bad_cursor = ByteCursor::new(&truncated_sid);
        assert_eq!(
            bad_cursor.read_sid("UserSID").map_err(DtoProcessError::from),
            Err(DtoProcessError::InvalidSid("UserSID"))
        );
    }

    /// Verifies zero-copy deserialization of modern Windows 10/11 Process V2 telemetry with dynamic-length SID, ANSI name, and UTF-16 command line.
    /// Essential to confirm pointer arithmetic correctly shifts across sequential variable-length fields in real kernel telemetry.
    #[test]
    fn test_process_v2_dto_deserialization() {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&(0xFFFF800011223344usize).to_ne_bytes()); // UniqueProcessKey
        buffer.extend_from_slice(&1000u32.to_ne_bytes()); // ProcessId
        buffer.extend_from_slice(&500u32.to_ne_bytes()); // ParentId
        buffer.extend_from_slice(&1u32.to_ne_bytes()); // SessionId
        buffer.extend_from_slice(&0i32.to_ne_bytes()); // ExitStatus
        buffer.extend_from_slice(&(0x100000usize).to_ne_bytes()); // DirectoryTableBase
        buffer.extend_from_slice(&[1u8, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0]); // UserSID (12 bytes)
        buffer.extend_from_slice(b"svchost.exe\0"); // ImageFileName (12 bytes)

        let cmdline: Vec<u8> = "svchost.exe -k netsvcs\0"
            .encode_utf16()
            .flat_map(|u| u.to_ne_bytes())
            .collect();
        buffer.extend_from_slice(&cmdline);

        let dto = Process_V2_TypeGroup1::try_from(buffer.as_slice())
            .expect("Valid Process_V2 payload should deserialize");

        assert_eq!(dto.ProcessId, 1000);
        assert_eq!(dto.ParentId, 500);
        assert_eq!(dto.SessionId, 1);
        assert_eq!(dto.ExitStatus, 0);
        assert_eq!(dto.ImageFileName, "svchost.exe");
        assert_eq!(
            crate::helpers::strings::decode_utf16le_bytes(dto.CommandLine),
            "svchost.exe -k netsvcs"
        );
    }

    /// Asserts that payloads terminating before the fixed header boundary are rejected with BufferTooShort.
    /// Prevents slice-indexing panics on truncated or corrupted ETW trace frames delivered during high system load.
    #[test]
    fn test_process_v2_dto_truncated_fixed_header() {
        let truncated = vec![0u8; std::mem::size_of::<usize>() + 8]; // Smaller than required fixed header size
        assert_eq!(
            Process_V2_TypeGroup1::try_from(truncated.as_slice()),
            Err(DtoProcessError::BufferTooShort("FixedHeader"))
        );
    }

    /// Validates legacy Windows 7/Vista V1 and XP V0 schema parsing to ensure backward-compatible ingestion.
    /// Mandatory to guarantee that legacy event formats or replay traces from older platforms do not cause agent crashes.
    #[test]
    fn test_process_v1_and_v0_schemas() {
        let mut v0_buf = Vec::new();
        v0_buf.extend_from_slice(&2000u32.to_ne_bytes()); // PID
        v0_buf.extend_from_slice(&1000u32.to_ne_bytes()); // ParentID
        v0_buf.extend_from_slice(&[1u8, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0]); // SID
        v0_buf.extend_from_slice(b"cmd.exe\0");

        let v0_dto = Process_V0_TypeGroup1::try_from(v0_buf.as_slice()).expect("V0 should parse");
        assert_eq!(v0_dto.ProcessId, 2000);
        assert_eq!(v0_dto.ParentId, 1000);
        assert_eq!(v0_dto.ImageFileName, "cmd.exe");
    }

    /// Verifies that 32-bit WOW64 Process_V3 payloads (4-byte pointers) deserialize accurately via ByteCursor.
    #[test]
    fn test_process_v3_32bit_pointer_size_deserialization() {
        let mut buf32 = Vec::new();
        buf32.extend_from_slice(&0x8123_4560u32.to_ne_bytes()); // UniqueProcessKey (4 bytes)
        buf32.extend_from_slice(&4444u32.to_ne_bytes()); // ProcessId
        buf32.extend_from_slice(&2222u32.to_ne_bytes()); // ParentId
        buf32.extend_from_slice(&2u32.to_ne_bytes()); // SessionId
        buf32.extend_from_slice(&0i32.to_ne_bytes()); // ExitStatus
        buf32.extend_from_slice(&0x001A_B000u32.to_ne_bytes()); // DirectoryTableBase (4 bytes)
        buf32.extend_from_slice(&0u32.to_ne_bytes()); // Flags
        buf32.extend_from_slice(&[1u8, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0]); // SID
        buf32.extend_from_slice(b"wow64app.exe\0");
        let cmdline: Vec<u8> = "wow64app.exe --32bit\0"
            .encode_utf16()
            .flat_map(|u| u.to_ne_bytes())
            .collect();
        buf32.extend_from_slice(&cmdline);

        let mut cur32 = ByteCursor::with_pointer_size(&buf32, 4);
        let dto = Process_V3_TypeGroup1::parse(&mut cur32).expect("32-bit V3 payload must parse");
        assert_eq!(dto.UniqueProcessKey, 0x8123_4560);
        assert_eq!(dto.ProcessId, 4444);
        assert_eq!(dto.ParentId, 2222);
        assert_eq!(dto.DirectoryTableBase, 0x001A_B000);
        assert_eq!(dto.ImageFileName, "wow64app.exe");
        assert_eq!(
            crate::helpers::strings::decode_utf16le_bytes(dto.CommandLine),
            "wow64app.exe --32bit"
        );
    }
}
