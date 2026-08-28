//! This file contains strongly-typed domain event types derived from the legacy NT Kernel Logger
//! ETW provider.
//!
//! Reference documentation:
//! <https://learn.microsoft.com/en-us/windows/win32/etw/process-v2>

use std::fmt;
use thiserror::Error;

use crate::model::security::Sid;
use crate::pipeline::etw_schemas::nt_kernel::process::{
    DtoProcessError, Process_V0_TypeGroup1, Process_V1_TypeGroup1, Process_V2_TypeGroup1,
};
use crate::sensors::etw::EventRecord;
use windows_sys::Win32::Foundation::STATUS_CONTROL_C_EXIT;

/// Domain-level error encountered while parsing and validating process events.
#[derive(Debug, Error)]
pub enum ProcessModelError {
    #[error("Unknown or unsupported ETW process opcode: {0}")]
    UnknownOpcode(u8),

    #[error("Unsupported schema version: {0}")]
    UnsupportedVersion(u8),

    #[error("Process DTO parse error: {0}")]
    Dto(#[from] DtoProcessError),

    #[error("Invalid SID: {0}")]
    InvalidSid(String),
}

/// Strongly-typed Process Identifier (PID).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProcessId(pub u32);

impl fmt::Display for ProcessId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Strongly-typed Windows Session Identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionId(pub u32);

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Kernel pointer address of the `EPROCESS` block uniquely identifying a process instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UniqueProcessKey(pub usize);

impl fmt::Display for UniqueProcessKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

/// Exit status outcome for terminated processes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExitStatus {
    Success,
    /// Process was forcefully terminated (killed, terminated via Ctrl+C / taskkill, or crashed).
    Terminated,
    Other(i32),
}

impl From<i32> for ExitStatus {
    fn from(code: i32) -> Self {
        match code {
            0 => Self::Success,
            // STATUS_CONTROL_C_EXIT (0xC000013A = -1073741510) indicates forced termination
            STATUS_CONTROL_C_EXIT | 1 => Self::Terminated,
            other => Self::Other(other),
        }
    }
}

impl fmt::Display for ExitStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Success => write!(f, "SUCCESS (0)"),
            Self::Terminated => write!(f, "TERMINATED"),
            Self::Other(code) => write!(f, "EXIT_CODE ({:#x})", code),
        }
    }
}

/// Identifies the specific lifecycle or telemetry event emitted by the ETW provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ProcessEventKind {
    /// Emitted in real-time when a new process is created and begins execution (EventType 1).
    Start = 1,

    /// Emitted in real-time when an active process terminates execution (EventType 2).
    /// Represents the point in time where all threads of the process have exited
    /// and the process exit code has been recorded.
    End = 2,

    /// Snapshot event representing a process that was already running when the
    /// ETW trace began (EventType 3, Data Collection Start). Emitted during the initial
    /// rundown phase to build a baseline of active processes.
    DCStart = 3,

    /// Snapshot event representing a process that was still active when the
    /// ETW trace stopped (EventType 4, Data Collection End). Distinguishes active processes
    /// from those that cleanly terminated or crashed mid-trace.
    DCEnd = 4,

    /// Snapshot event representing a terminated process whose kernel object (`EPROCESS`)
    /// still lingers in memory (EventType 39, Defunct). Emitted during rundown for
    /// "zombie" processes holding unclosed handles.
    Defunct = 39,
}

/// Implement TryFrom trait as a helper to translate only the defined opcodes
/// in ProcessEventKind and error on any other opcode.
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

/// Unified domain event representing a process lifecycle change or telemetry record.
/// Note: Since this is a telemetry event might be ephimer and its values might be **moved** to
/// a bigger longliving structure where more process information data is collected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessEvent {
    // Header & Event Ingestion Context
    pub timestamp: i64,
    pub emitter_pid: ProcessId,
    pub emitter_tid: u32,
    pub stack_trace: Option<Vec<u64>>,
    pub kind: ProcessEventKind,

    // Process Hierarchy & Identification
    /// Kernel address of the `EPROCESS` block.
    pub unique_process_key: UniqueProcessKey,
    pub process_id: ProcessId,
    pub parent_id: ProcessId,
    pub session_id: SessionId,

    // Execution Outcome & Identity
    /// Exit status is `None` for `Start` or `DCStart` event types,
    /// and `Some` for `End` / `Defunct` event types.
    pub exit_status: Option<ExitStatus>,
    pub user_sid: Sid,
    pub image_file_name: String,
    pub command_line: String,
}

impl TryFrom<&EventRecord> for ProcessEvent {
    type Error = ProcessModelError;

    fn try_from(record: &EventRecord) -> Result<Self, Self::Error> {
        let kind = ProcessEventKind::try_from(record.opcode)?;
        let bytes = record.user_data.as_slice();

        match record.version {
            2 => {
                let dto = Process_V2_TypeGroup1::try_from(bytes)?;
                ProcessEvent::from_v2(record, kind, &dto)
            }
            1 => {
                let dto = Process_V1_TypeGroup1::try_from(bytes)?;
                ProcessEvent::from_v1(record, kind, &dto)
            }
            0 => {
                let dto = Process_V0_TypeGroup1::try_from(bytes)?;
                ProcessEvent::from_v0(record, kind, &dto)
            }
            v => Err(ProcessModelError::UnsupportedVersion(v)),
        }
    }
}

impl ProcessEvent {
    /// Constructs a `ProcessEvent` from modern Windows 8+ (Version 2) schema payload.
    fn from_v2(
        record: &EventRecord,
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
            timestamp: record.timestamp,
            emitter_pid: ProcessId(record.process_id),
            emitter_tid: record.thread_id,
            stack_trace: record.stack_trace.clone(),
            kind,

            unique_process_key: UniqueProcessKey(dto.UniqueProcessKey),
            process_id: ProcessId(dto.ProcessId),
            parent_id: ProcessId(dto.ParentId),
            session_id: SessionId(dto.SessionId),

            exit_status,
            user_sid,
            image_file_name: dto.ImageFileName.to_string(),
            command_line: String::from_utf16_lossy(dto.CommandLine),
        })
    }

    /// Constructs a `ProcessEvent` from Windows Vista / 7 (Version 1) schema payload.
    fn from_v1(
        record: &EventRecord,
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
            timestamp: record.timestamp,
            emitter_pid: ProcessId(record.process_id),
            emitter_tid: record.thread_id,
            stack_trace: record.stack_trace.clone(),
            kind,

            unique_process_key: UniqueProcessKey(dto.PageDirectoryBase),
            process_id: ProcessId(dto.ProcessId),
            parent_id: ProcessId(dto.ParentId),
            session_id: SessionId(dto.SessionId),

            exit_status,
            user_sid,
            image_file_name: dto.ImageFileName.to_string(),
            command_line: String::new(), // V1 did not capture command lines
        })
    }

    /// Constructs a `ProcessEvent` from legacy Windows XP / 2003 (Version 0) schema payload.
    fn from_v0(
        record: &EventRecord,
        kind: ProcessEventKind,
        dto: &Process_V0_TypeGroup1,
    ) -> Result<Self, ProcessModelError> {
        let user_sid =
            Sid::try_from(dto.UserSID).map_err(|e| ProcessModelError::InvalidSid(e.to_string()))?;

        Ok(Self {
            timestamp: record.timestamp,
            emitter_pid: ProcessId(record.process_id),
            emitter_tid: record.thread_id,
            stack_trace: record.stack_trace.clone(),
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
