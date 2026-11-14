//! Strongly-typed domain event types for kernel process lifecycle telemetry (`ProcessEvent`).
//!
//! # Role in the Architecture
//!
//! [`ProcessEvent`] normalizes versioned kernel MOF DTOs (`Process_V0..V4_TypeGroup1`) into a
//! single version-independent domain representation consumed by [`ProcessContextSink`](crate::sinks::ProcessContextSink)
//! and [`DetectionSink`](crate::sinks::DetectionSink).
//!
//! Supports zero-copy decoding directly from `&RawEvent` (via `TryFrom<&RawEvent>`) inside
//! [`PipelineEventRouter`](crate::pipeline::PipelineEventRouter), as well as decoding from an
//! owned [`EventRecord`] in tests.
//!
//! Reference: <https://learn.microsoft.com/en-us/windows/win32/etw/process-v2>

use std::fmt;
use thiserror::Error;

use crate::model::security::Sid;
use crate::model::types::{ExitStatus, ProcessId, SessionId, StackTrace, UniqueProcessKey};
use crate::pipeline::etw_schemas::nt_kernel::process::{
    DtoProcessError, Process_V0_TypeGroup1, Process_V1_TypeGroup1, Process_V2_TypeGroup1,
    Process_V3_TypeGroup1,
};
use crate::sensors::etw::{EventRecord, RawEvent};

/// Domain-level error encountered while parsing and validating process lifecycle events.
#[derive(Debug, Error)]
pub enum ProcessModelError {
    /// The ETW event header carried an opcode other than `1`, `2`, `3`, `4`, or `39`.
    #[error("Unknown or unsupported ETW process opcode: {0}")]
    UnknownOpcode(u8),

    /// The ETW event header specified an unsupported schema version.
    #[error("Unsupported schema version: {0}")]
    UnsupportedVersion(u8),

    /// The underlying binary `UserData` payload failed DTO schema decoding.
    #[error("Process DTO parse error: {0}")]
    Dto(#[from] DtoProcessError),

    /// The extracted binary `UserSID` slice could not be converted into a valid [`Sid`].
    #[error("Invalid SID: {0}")]
    InvalidSid(String),
}

/// Identifies the specific lifecycle transition or rundown snapshot represented by a [`ProcessEvent`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ProcessEventKind {
    /// Emitted in real-time when a new process is created and begins execution (`Opcode = 1`).
    Start = 1,

    /// Emitted in real-time when an active process terminates execution (`Opcode = 2`).
    ///
    /// Represents the point in time where all threads of the process have exited and the
    /// process exit status code has been recorded.
    End = 2,

    /// Snapshot event representing a process that was already running when the ETW session
    /// started (`Opcode = 3`, Data Collection Start).
    ///
    /// Emitted during the initial kernel rundown phase so [`ProcessContextSink`](crate::sinks::ProcessContextSink)
    /// can populate the baseline process tree without calling `CreateToolhelp32Snapshot`.
    DCStart = 3,

    /// Snapshot event representing a process that was still active when the ETW session
    /// stopped (`Opcode = 4`, Data Collection End).
    DCEnd = 4,

    /// Snapshot event representing a terminated process whose kernel `_EPROCESS` object
    /// still lingers in memory (`Opcode = 39`, Defunct) because another process holds an
    /// unclosed handle to it.
    Defunct = 39,
}

impl TryFrom<u8> for ProcessEventKind {
    type Error = ProcessModelError;

    fn try_from(opcode: u8) -> Result<Self, Self::Error> {
        match opcode {
            1 => Ok(Self::Start),
            2 => Ok(Self::End),
            3 => Ok(Self::DCStart),
            4 => Ok(Self::DCEnd),
            39 => Ok(Self::Defunct),
            unknown => Err(ProcessModelError::UnknownOpcode(unknown)),
        }
    }
}

impl fmt::Display for ProcessEventKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Start => write!(f, "START"),
            Self::End => write!(f, "END"),
            Self::DCStart => write!(f, "DC_START"),
            Self::DCEnd => write!(f, "DC_END"),
            Self::Defunct => write!(f, "DEFUNCT"),
        }
    }
}

/// Normalized domain event representing a process creation, termination, or rundown snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessEvent {
    /// Raw QPC timestamp when the kernel logged the event (`EventHeader.TimeStamp`).
    pub timestamp: i64,
    /// PID of the thread that logged the event (`EventHeader.ProcessId`, typically the creator/parent on `Start`).
    pub emitter_pid: ProcessId,
    /// TID of the thread that logged the event (`EventHeader.ThreadId`).
    pub emitter_tid: u32,
    /// Optional inline or correlated call stack frames.
    pub stack_trace: Option<StackTrace>,
    /// Lifecycle transition kind (`Start`, `End`, `DCStart`, `DCEnd`, or `Defunct`).
    pub kind: ProcessEventKind,

    /// Kernel address of the `_EPROCESS` structure (`UniqueProcessKey`).
    pub unique_process_key: UniqueProcessKey,
    /// Target Process ID of the process being created, enumerated, or terminated.
    pub process_id: ProcessId,
    /// Parent Process ID (`InheritedFromUniqueProcessId`).
    pub parent_id: ProcessId,
    /// Terminal Services session ID under which the process runs.
    pub session_id: SessionId,

    /// Process exit status (`None` on `Start`/`DCStart`/`DCEnd`, `Some(ExitStatus)` on `End`/`Defunct`).
    pub exit_status: Option<ExitStatus>,
    /// Security Identifier (`SID`) of the primary process token.
    pub user_sid: Sid,
    /// Short executable file name from `_EPROCESS.ImageFileName` (e.g., `"svchost.exe"`).
    pub image_file_name: String,
    /// Full process command line decoded from UTF-16LE (empty on legacy V0/V1 schemas).
    pub command_line: String,
}

impl ProcessEvent {
    /// Constructs a [`ProcessEvent`] from a decoded Version 3 / Version 4+ DTO.
    #[inline]
    fn build_from_v3(
        timestamp: i64,
        emitter_pid: u32,
        emitter_tid: u32,
        stack_trace: Option<StackTrace>,
        kind: ProcessEventKind,
        dto: &Process_V3_TypeGroup1,
    ) -> Result<Self, ProcessModelError> {
        let user_sid =
            Sid::try_from(dto.UserSID).map_err(|e| ProcessModelError::InvalidSid(e.to_string()))?;

        let exit_status = match kind {
            ProcessEventKind::End | ProcessEventKind::Defunct => {
                Some(ExitStatus::from(dto.ExitStatus))
            }
            _ => None,
        };

        Ok(Self {
            timestamp,
            emitter_pid: ProcessId(emitter_pid),
            emitter_tid,
            stack_trace,
            kind,
            unique_process_key: UniqueProcessKey(dto.UniqueProcessKey),
            process_id: ProcessId(dto.ProcessId),
            parent_id: ProcessId(dto.ParentId),
            session_id: SessionId(dto.SessionId),
            exit_status,
            user_sid,
            image_file_name: dto.ImageFileName.to_string(),
            command_line: crate::helpers::strings::decode_utf16le_bytes(dto.CommandLine),
        })
    }

    /// Constructs a [`ProcessEvent`] from a decoded Version 2 DTO.
    #[inline]
    fn build_from_v2(
        timestamp: i64,
        emitter_pid: u32,
        emitter_tid: u32,
        stack_trace: Option<StackTrace>,
        kind: ProcessEventKind,
        dto: &Process_V2_TypeGroup1,
    ) -> Result<Self, ProcessModelError> {
        let user_sid =
            Sid::try_from(dto.UserSID).map_err(|e| ProcessModelError::InvalidSid(e.to_string()))?;

        let exit_status = match kind {
            ProcessEventKind::End | ProcessEventKind::Defunct => {
                Some(ExitStatus::from(dto.ExitStatus))
            }
            _ => None,
        };

        Ok(Self {
            timestamp,
            emitter_pid: ProcessId(emitter_pid),
            emitter_tid,
            stack_trace,
            kind,
            unique_process_key: UniqueProcessKey(dto.UniqueProcessKey),
            process_id: ProcessId(dto.ProcessId),
            parent_id: ProcessId(dto.ParentId),
            session_id: SessionId(dto.SessionId),
            exit_status,
            user_sid,
            image_file_name: dto.ImageFileName.to_string(),
            command_line: crate::helpers::strings::decode_utf16le_bytes(dto.CommandLine),
        })
    }

    /// Constructs a [`ProcessEvent`] from a decoded Version 1 DTO.
    #[inline]
    fn build_from_v1(
        timestamp: i64,
        emitter_pid: u32,
        emitter_tid: u32,
        stack_trace: Option<StackTrace>,
        kind: ProcessEventKind,
        dto: &Process_V1_TypeGroup1,
    ) -> Result<Self, ProcessModelError> {
        let user_sid =
            Sid::try_from(dto.UserSID).map_err(|e| ProcessModelError::InvalidSid(e.to_string()))?;

        let exit_status = match kind {
            ProcessEventKind::End | ProcessEventKind::Defunct => {
                Some(ExitStatus::from(dto.ExitStatus))
            }
            _ => None,
        };

        Ok(Self {
            timestamp,
            emitter_pid: ProcessId(emitter_pid),
            emitter_tid,
            stack_trace,
            kind,
            unique_process_key: UniqueProcessKey(dto.PageDirectoryBase),
            process_id: ProcessId(dto.ProcessId),
            parent_id: ProcessId(dto.ParentId),
            session_id: SessionId(dto.SessionId),
            exit_status,
            user_sid,
            image_file_name: dto.ImageFileName.to_string(),
            command_line: String::new(),
        })
    }

    /// Constructs a [`ProcessEvent`] from a decoded Version 0 DTO.
    #[inline]
    fn build_from_v0(
        timestamp: i64,
        emitter_pid: u32,
        emitter_tid: u32,
        stack_trace: Option<StackTrace>,
        kind: ProcessEventKind,
        dto: &Process_V0_TypeGroup1,
    ) -> Result<Self, ProcessModelError> {
        let user_sid =
            Sid::try_from(dto.UserSID).map_err(|e| ProcessModelError::InvalidSid(e.to_string()))?;

        Ok(Self {
            timestamp,
            emitter_pid: ProcessId(emitter_pid),
            emitter_tid,
            stack_trace,
            kind,
            unique_process_key: UniqueProcessKey(0),
            process_id: ProcessId(dto.ProcessId),
            parent_id: ProcessId(dto.ParentId),
            session_id: SessionId(0),
            exit_status: None,
            user_sid,
            image_file_name: dto.ImageFileName.to_string(),
            command_line: String::new(),
        })
    }
}

impl TryFrom<&RawEvent> for ProcessEvent {
    type Error = ProcessModelError;

    #[inline]
    fn try_from(event: &RawEvent) -> Result<Self, Self::Error> {
        let kind = ProcessEventKind::try_from(event.opcode())?;
        let stack_trace = event.extract_call_stack().map(StackTrace::new);

        match event.version() {
            3.. => {
                let dto = Process_V3_TypeGroup1::try_from(event)?;
                Self::build_from_v3(
                    event.timestamp(),
                    event.process_id(),
                    event.thread_id(),
                    stack_trace,
                    kind,
                    &dto,
                )
            }
            2 => {
                let dto = Process_V2_TypeGroup1::try_from(event)?;
                Self::build_from_v2(
                    event.timestamp(),
                    event.process_id(),
                    event.thread_id(),
                    stack_trace,
                    kind,
                    &dto,
                )
            }
            1 => {
                let dto = Process_V1_TypeGroup1::try_from(event)?;
                Self::build_from_v1(
                    event.timestamp(),
                    event.process_id(),
                    event.thread_id(),
                    stack_trace,
                    kind,
                    &dto,
                )
            }
            0 => {
                let dto = Process_V0_TypeGroup1::try_from(event)?;
                Self::build_from_v0(
                    event.timestamp(),
                    event.process_id(),
                    event.thread_id(),
                    stack_trace,
                    kind,
                    &dto,
                )
            }
        }
    }
}

impl TryFrom<&EventRecord> for ProcessEvent {
    type Error = ProcessModelError;

    #[inline]
    fn try_from(record: &EventRecord) -> Result<Self, Self::Error> {
        let kind = ProcessEventKind::try_from(record.opcode)?;
        let bytes = record.user_data.as_slice();
        let stack_trace = record.stack_trace.clone().map(StackTrace::new);

        match record.version {
            3.. => {
                let dto = Process_V3_TypeGroup1::try_from(bytes)?;
                Self::build_from_v3(
                    record.timestamp,
                    record.process_id,
                    record.thread_id,
                    stack_trace,
                    kind,
                    &dto,
                )
            }
            2 => {
                let dto = Process_V2_TypeGroup1::try_from(bytes)?;
                Self::build_from_v2(
                    record.timestamp,
                    record.process_id,
                    record.thread_id,
                    stack_trace,
                    kind,
                    &dto,
                )
            }
            1 => {
                let dto = Process_V1_TypeGroup1::try_from(bytes)?;
                Self::build_from_v1(
                    record.timestamp,
                    record.process_id,
                    record.thread_id,
                    stack_trace,
                    kind,
                    &dto,
                )
            }
            0 => {
                let dto = Process_V0_TypeGroup1::try_from(bytes)?;
                Self::build_from_v0(
                    record.timestamp,
                    record.process_id,
                    record.thread_id,
                    stack_trace,
                    kind,
                    &dto,
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sensors::etw::SyntheticEvent;
    use windows_sys::core::GUID;

    /// Verifies complete transformation from raw EventRecord and RawEvent into strongly-typed ProcessEvent.
    #[test]
    fn test_process_event_from_v2_raw_event_and_record() {
        let mut user_data = Vec::new();
        user_data.extend_from_slice(&(0xAAAA_BBBBusize).to_ne_bytes()); // UniqueProcessKey
        user_data.extend_from_slice(&4321u32.to_ne_bytes()); // PID
        user_data.extend_from_slice(&1234u32.to_ne_bytes()); // Parent PID
        user_data.extend_from_slice(&1u32.to_ne_bytes()); // Session ID
        user_data.extend_from_slice(&0i32.to_ne_bytes()); // ExitStatus
        user_data.extend_from_slice(&(0x200000usize).to_ne_bytes()); // DirectoryTableBase
        user_data.extend_from_slice(&[1u8, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0]); // SID S-1-5-18
        user_data.extend_from_slice(b"consent.exe\0");
        let cmd: Vec<u8> = "consent.exe 123\0"
            .encode_utf16()
            .flat_map(|u| u.to_ne_bytes())
            .collect();
        user_data.extend_from_slice(&cmd);

        let provider_id = GUID {
            data1: 0x3d6fa8d0,
            data2: 0xfe05,
            data3: 0x11d0,
            data4: [0x9d, 0xda, 0x00, 0xc0, 0x4f, 0xd7, 0xba, 0x7c],
        };

        let syn_start =
            SyntheticEvent::new(provider_id, 2, 1, 4321, 100, 555_000, user_data.clone());
        let start_event =
            ProcessEvent::try_from(syn_start.as_raw_event()).expect("RawEvent Start should parse");
        assert_eq!(start_event.kind, ProcessEventKind::Start);
        assert_eq!(start_event.process_id, ProcessId(4321));
        assert_eq!(start_event.exit_status, None);
        assert_eq!(start_event.image_file_name, "consent.exe");

        let syn_end = SyntheticEvent::new(provider_id, 2, 2, 4321, 100, 555_000, user_data);
        let end_event =
            ProcessEvent::try_from(syn_end.as_raw_event()).expect("RawEvent End should parse");
        assert_eq!(end_event.kind, ProcessEventKind::End);
        assert_eq!(end_event.exit_status, Some(ExitStatus::Success));
    }
}
