//! This file contains event types derived from the legacy NT Kernel Logger
//! ETW provider events.

// The reference documentation for this structure is here:
// https://learn.microsoft.com/en-us/windows/win32/etw/process-v2

use crate::model::security::Sid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProcessId(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionId(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Eprocess(pub usize);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExitStatus {
    Success,
    /// Process was forcefully terminated (a.k.a killed)
    Terminated,
    Other(i32),
}

/// Emitted in real-time when an active process terminates execution.
///
/// Corresponds to EventType. Represents the point in time where all
/// threads of the process have exited and the process exit code has been recorded.
pub struct ProcessEndEvent {
    /// The address of the EPROCESS object in the kernel
    pub unique_process_key: Eprocess,
    pub process_id: ProcessId,
    pub parent_id: ProcessId,
    pub session_id: SessionId,
    pub exit_status: ExitStatus,
    pub user_sid: Sid,
    pub image_file_name: String,
    pub command_line: String,
}

/// Emitted in real-time when a new process is created and begins execution.
///
/// Corresponds to EventType 1. Provides initial metadata about the spawned
/// process including identifiers, the executable path, command line arguments, and the
/// creating user context.
pub struct ProcessStartEvent {}

/// Snapshot event representing a process that was already running when the ETW trace began.
///
/// Corresponds to EventType 3 (DCStart / Data Collection Start). Emitted during the
/// initial rundown phase so downstream consumers can build a complete baseline of active
/// system processes without having observed their initial [`ProcessStartEvent`].
pub struct ProcessDCStartEvent {}

/// Snapshot event representing a process that was still active when the ETW trace stopped.
///
/// Corresponds to EventType 4 (DCEnd / Data Collection End). Emitted during the trace
/// rundown/teardown phase to mark processes that remained alive through the end of data
/// collection, distinguishing them from processes that cleanly exited or crashed mid-trace.
pub struct ProcessDCEndEvent {}

/// Snapshot event representing a terminated process whose kernel object (`EPROCESS`)
/// still lingers in memory.
///
/// Corresponds to EventType 39 (Defunct). Emitted during rundown enumeration for
/// "zombie" processes that have finished execution, but whose kernel structures cannot
/// yet be freed because one or more open handles remain held by other processes or drivers.
pub struct ProcessDefunctEvent {}
