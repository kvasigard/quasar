/// Event types for ETW Kernel Process tracing:
///
/// +-------+---------------------------------+----------------------------------------------------+-----------------------+
/// | Value | Constant / Event Name           | Description                                        | MOF Class             |
/// +-------+---------------------------------+----------------------------------------------------+-----------------------+
/// | 1     | EVENT_TRACE_TYPE_START          | Start process event.                               | Process_V2_TypeGroup1 |
/// | 2     | EVENT_TRACE_TYPE_END            | End process event.                                 | Process_V2_TypeGroup1 |
/// | 3     | EVENT_TRACE_TYPE_DC_START       | Start data collection (enumerates running at start)| Process_V2_TypeGroup1 |
/// | 4     | EVENT_TRACE_TYPE_DC_END         | End data collection (enumerates running at end)    | Process_V2_TypeGroup1 |
/// | 32    | Performance Counters            | Performance counters event.                        | Process_V2_TypeGroup2 |
/// | 33    | Performance Counters Rundown    | Rundown of performance counters at session start.  | Process_V2_TypeGroup2 |
/// | 39    | Defunct Process                 | Defunct process event.                             | Process_V2_TypeGroup1 |
/// +-------+---------------------------------+----------------------------------------------------+-----------------------+
///
/// Process and thread start events may be logged in the context of the parent process or thread.
/// As a result, the ProcessId and ThreadId members of EVENT_TRACE_HEADER may not correspond to
/// the process and thread being created. This is why these events contain the process and thread
/// identifiers in the event data (in addition to those in the event header).
///
/// Reference: https://learn.microsoft.com/en-us/windows/win32/etw/process-v2
use crate::helpers::strings::{StringError, parse_ansi_string, parse_utf16_slice};
use thiserror::Error;

const PTR_SIZE: usize = std::mem::size_of::<usize>();

/// Specific error type for Process ETW DTO parsing failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum DtoProcessError {
    #[error("Buffer too short for field '{0}'")]
    BufferTooShort(&'static str),

    #[error("Invalid binary SID in field '{0}'")]
    InvalidSid(&'static str),

    #[error("String parsing error in field '{0}': {1}")]
    String(&'static str, #[source] StringError),
}

/// Extracts a zero-copy slice of a Windows binary Security Identifier (SID).
///
/// The Windows SID Binary Layout as described in `WinNT.h` looks like the following:
/// ```text
/// +--------+-------------------+-----------------------+---------------------------------------+
/// | Offset | Size (Bytes)      | Field                 | Description                           |
/// +--------+-------------------+-----------------------+---------------------------------------+
/// | 0x00   | 1 (BYTE)          | Revision              | SID structure revision (always 1)     |
/// | 0x01   | 1 (BYTE)          | SubAuthorityCount (N) | Number of 32-bit sub-authority values |
/// | 0x02   | 6 (BYTE[6])       | IdentifierAuthority   | 48-bit authority identifier (e.g., NT)|
/// | 0x08   | N * 4 (DWORD[N])  | SubAuthority Array    | N x 32-bit integers (e.g., RIDs)      |
/// +--------+-------------------+-----------------------+---------------------------------------+
/// Total SID Size = 8 bytes (Header) + (SubAuthorityCount * 4 bytes)
/// Example: S-1-5-21-1234-5678-9012-500 has N=5 sub-authorities -> 8 + (5 * 4) = 28 bytes.
/// ```
///
/// # Arguments
/// * `bytes` - Byte slice starting at the SID boundary.
/// * `field` - Field name for error reporting.
///
/// # Returns
/// A tuple containing:
/// * `&[u8]` - Zero-copy subslice containing the exact binary SID bytes.
/// * `usize` - Total number of bytes consumed by the SID.
#[inline]
fn parse_sid<'a>(
    bytes: &'a [u8],
    field: &'static str,
) -> Result<(&'a [u8], usize), DtoProcessError> {
    if bytes.len() < 8 {
        return Err(DtoProcessError::BufferTooShort(field));
    }

    let sub_auth_count = bytes[1] as usize;
    let sid_len = 8 + (sub_auth_count * 4);

    if bytes.len() < sid_len {
        return Err(DtoProcessError::InvalidSid(field));
    }

    Ok((&bytes[..sid_len], sid_len))
}

// V0 Process Schema (Windows XP / Server 2003)
#[allow(nonstandard_style)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Process_V0_TypeGroup1<'a> {
    pub ProcessId: u32,
    pub ParentId: u32,
    pub UserSID: &'a [u8],
    pub ImageFileName: &'a str,
}

impl<'a> TryFrom<&'a [u8]> for Process_V0_TypeGroup1<'a> {
    type Error = DtoProcessError;

    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        if bytes.len() < 8 {
            return Err(DtoProcessError::BufferTooShort("FixedHeader"));
        }

        let process_id = u32::from_ne_bytes(bytes[0..4].try_into().unwrap());
        let parent_id = u32::from_ne_bytes(bytes[4..8].try_into().unwrap());
        let mut offset = 8;

        let (user_sid, sid_len) = parse_sid(&bytes[offset..], "UserSID")?;
        offset += sid_len;

        let (image_file_name, _) = parse_ansi_string(&bytes[offset..])
            .map_err(|source| DtoProcessError::String("ImageFileName", source))?;

        Ok(Self {
            ProcessId: process_id,
            ParentId: parent_id,
            UserSID: user_sid,
            ImageFileName: image_file_name,
        })
    }
}

// V1 Process Schema (Windows Vista / 7 / Server 2008)
#[allow(nonstandard_style)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Process_V1_TypeGroup1<'a> {
    pub PageDirectoryBase: usize,
    pub ProcessId: u32,
    pub ParentId: u32,
    pub SessionId: u32,
    pub ExitStatus: i32,
    pub UserSID: &'a [u8],
    pub ImageFileName: &'a str,
}

impl<'a> TryFrom<&'a [u8]> for Process_V1_TypeGroup1<'a> {
    type Error = DtoProcessError;

    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        let fixed_size = PTR_SIZE + 16;
        if bytes.len() < fixed_size {
            return Err(DtoProcessError::BufferTooShort("FixedHeader"));
        }

        let mut offset = 0;
        let page_directory_base =
            usize::from_ne_bytes(bytes[offset..offset + PTR_SIZE].try_into().unwrap());
        offset += PTR_SIZE;

        let process_id = u32::from_ne_bytes(bytes[offset..offset + 4].try_into().unwrap());
        offset += 4;
        let parent_id = u32::from_ne_bytes(bytes[offset..offset + 4].try_into().unwrap());
        offset += 4;
        let session_id = u32::from_ne_bytes(bytes[offset..offset + 4].try_into().unwrap());
        offset += 4;
        let exit_status = i32::from_ne_bytes(bytes[offset..offset + 4].try_into().unwrap());
        offset += 4;

        let (user_sid, sid_len) = parse_sid(&bytes[offset..], "UserSID")?;
        offset += sid_len;

        let (image_file_name, _) = parse_ansi_string(&bytes[offset..])
            .map_err(|source| DtoProcessError::String("ImageFileName", source))?;

        Ok(Self {
            PageDirectoryBase: page_directory_base,
            ProcessId: process_id,
            ParentId: parent_id,
            SessionId: session_id,
            ExitStatus: exit_status,
            UserSID: user_sid,
            ImageFileName: image_file_name,
        })
    }
}

// V2 Process Schema (Windows 8 / 10 / 11 / Server 2012+)
#[allow(nonstandard_style)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Process_V2_TypeGroup1<'a> {
    pub UniqueProcessKey: usize,
    pub ProcessId: u32,
    pub ParentId: u32,
    pub SessionId: u32,
    pub ExitStatus: i32,
    pub DirectoryTableBase: usize,
    pub UserSID: &'a [u8],
    pub ImageFileName: &'a str,
    pub CommandLine: &'a [u16],
}

impl<'a> TryFrom<&'a [u8]> for Process_V2_TypeGroup1<'a> {
    type Error = DtoProcessError;

    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        let fixed_size = PTR_SIZE + 16 + PTR_SIZE;
        if bytes.len() < fixed_size {
            return Err(DtoProcessError::BufferTooShort("FixedHeader"));
        }

        let mut offset = 0;
        let unique_process_key =
            usize::from_ne_bytes(bytes[offset..offset + PTR_SIZE].try_into().unwrap());
        offset += PTR_SIZE;

        let process_id = u32::from_ne_bytes(bytes[offset..offset + 4].try_into().unwrap());
        offset += 4;
        let parent_id = u32::from_ne_bytes(bytes[offset..offset + 4].try_into().unwrap());
        offset += 4;
        let session_id = u32::from_ne_bytes(bytes[offset..offset + 4].try_into().unwrap());
        offset += 4;
        let exit_status = i32::from_ne_bytes(bytes[offset..offset + 4].try_into().unwrap());
        offset += 4;

        let directory_table_base =
            usize::from_ne_bytes(bytes[offset..offset + PTR_SIZE].try_into().unwrap());
        offset += PTR_SIZE;

        let (user_sid, sid_len) = parse_sid(&bytes[offset..], "UserSID")?;
        offset += sid_len;

        let (image_file_name, name_len) = parse_ansi_string(&bytes[offset..])
            .map_err(|source| DtoProcessError::String("ImageFileName", source))?;
        offset += name_len;

        let (command_line, _) = parse_utf16_slice(&bytes[offset..])
            .map_err(|source| DtoProcessError::String("CommandLine", source))?;

        Ok(Self {
            UniqueProcessKey: unique_process_key,
            ProcessId: process_id,
            ParentId: parent_id,
            SessionId: session_id,
            ExitStatus: exit_status,
            DirectoryTableBase: directory_table_base,
            UserSID: user_sid,
            ImageFileName: image_file_name,
            CommandLine: command_line,
        })
    }
}

// V2 Performance Counters Schema (Opcode 32 / 33)
#[allow(nonstandard_style)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Process_V2_TypeGroup2 {
    pub UniqueProcessKey: usize,
    pub ProcessId: u32,
    pub UserTime: u64,
    pub KernelTime: u64,
    pub PeakVirtualSize: usize,
    pub PeakWorkingSetSize: usize,
    pub VirtualSize: usize,
    pub PagefileUsage: usize,
    pub PeakPagefileUsage: usize,
    pub WorkingSetSize: usize,
    pub PageFaultCount: u32,
    pub HardFaultCount: u32,
    pub CommitCharge: usize,
    pub PeakCommitCharge: usize,
    pub ReadOperationCount: u64,
    pub WriteOperationCount: u64,
    pub OtherOperationCount: u64,
    pub ReadTransferCount: u64,
    pub WriteTransferCount: u64,
    pub OtherTransferCount: u64,
}

impl TryFrom<&[u8]> for Process_V2_TypeGroup2 {
    type Error = DtoProcessError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let total_size = (9 * PTR_SIZE) + 12 + 64;
        if bytes.len() < total_size {
            return Err(DtoProcessError::BufferTooShort("FixedHeader"));
        }

        let mut offset = 0;

        let unique_process_key =
            usize::from_ne_bytes(bytes[offset..offset + PTR_SIZE].try_into().unwrap());
        offset += PTR_SIZE;

        let process_id = u32::from_ne_bytes(bytes[offset..offset + 4].try_into().unwrap());
        offset += 4;

        let user_time = u64::from_ne_bytes(bytes[offset..offset + 8].try_into().unwrap());
        offset += 8;

        let kernel_time = u64::from_ne_bytes(bytes[offset..offset + 8].try_into().unwrap());
        offset += 8;

        let peak_virtual_size =
            usize::from_ne_bytes(bytes[offset..offset + PTR_SIZE].try_into().unwrap());
        offset += PTR_SIZE;

        let peak_working_set_size =
            usize::from_ne_bytes(bytes[offset..offset + PTR_SIZE].try_into().unwrap());
        offset += PTR_SIZE;

        let virtual_size =
            usize::from_ne_bytes(bytes[offset..offset + PTR_SIZE].try_into().unwrap());
        offset += PTR_SIZE;

        let pagefile_usage =
            usize::from_ne_bytes(bytes[offset..offset + PTR_SIZE].try_into().unwrap());
        offset += PTR_SIZE;

        let peak_pagefile_usage =
            usize::from_ne_bytes(bytes[offset..offset + PTR_SIZE].try_into().unwrap());
        offset += PTR_SIZE;

        let working_set_size =
            usize::from_ne_bytes(bytes[offset..offset + PTR_SIZE].try_into().unwrap());
        offset += PTR_SIZE;

        let page_fault_count = u32::from_ne_bytes(bytes[offset..offset + 4].try_into().unwrap());
        offset += 4;

        let hard_fault_count = u32::from_ne_bytes(bytes[offset..offset + 4].try_into().unwrap());
        offset += 4;

        let commit_charge =
            usize::from_ne_bytes(bytes[offset..offset + PTR_SIZE].try_into().unwrap());
        offset += PTR_SIZE;

        let peak_commit_charge =
            usize::from_ne_bytes(bytes[offset..offset + PTR_SIZE].try_into().unwrap());
        offset += PTR_SIZE;

        let read_operation_count =
            u64::from_ne_bytes(bytes[offset..offset + 8].try_into().unwrap());
        offset += 8;

        let write_operation_count =
            u64::from_ne_bytes(bytes[offset..offset + 8].try_into().unwrap());
        offset += 8;

        let other_operation_count =
            u64::from_ne_bytes(bytes[offset..offset + 8].try_into().unwrap());
        offset += 8;

        let read_transfer_count = u64::from_ne_bytes(bytes[offset..offset + 8].try_into().unwrap());
        offset += 8;

        let write_transfer_count =
            u64::from_ne_bytes(bytes[offset..offset + 8].try_into().unwrap());
        offset += 8;

        let other_transfer_count =
            u64::from_ne_bytes(bytes[offset..offset + 8].try_into().unwrap());

        Ok(Self {
            UniqueProcessKey: unique_process_key,
            ProcessId: process_id,
            UserTime: user_time,
            KernelTime: kernel_time,
            PeakVirtualSize: peak_virtual_size,
            PeakWorkingSetSize: peak_working_set_size,
            VirtualSize: virtual_size,
            PagefileUsage: pagefile_usage,
            PeakPagefileUsage: peak_pagefile_usage,
            WorkingSetSize: working_set_size,
            PageFaultCount: page_fault_count,
            HardFaultCount: hard_fault_count,
            CommitCharge: commit_charge,
            PeakCommitCharge: peak_commit_charge,
            ReadOperationCount: read_operation_count,
            WriteOperationCount: write_operation_count,
            OtherOperationCount: other_operation_count,
            ReadTransferCount: read_transfer_count,
            WriteTransferCount: write_transfer_count,
            OtherTransferCount: other_transfer_count,
        })
    }
}
