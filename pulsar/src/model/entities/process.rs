//! Domain entities representing long-lived process state.

use std::sync::RwLock;
use std::sync::atomic::AtomicBool;

use crate::model::security::Sid;
use crate::model::types::{ExitStatus, ProcessId, SessionId, UniqueProcessKey};

/// Unique composite key identifying a process instance (PID + Creation Time).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProcessKey {
    pub pid: ProcessId,
    pub creation_timestamp: i64,
}

impl ProcessKey {
    pub fn new(pid: ProcessId, creation_timestamp: i64) -> Self {
        // TODO: Validate that the PID is valid and the timestamp is not in the future
        Self {
            pid,
            creation_timestamp,
        }
    }
}

/// Long-lived state representation of a running or terminated process.
#[derive(Debug)]
pub struct ProcessNode {
    // Immutable identity established at start
    pub process_id: ProcessId,
    pub creation_timestamp: i64,
    pub parent_pid: ProcessId,
    pub unique_process_key: UniqueProcessKey,
    pub session_id: SessionId,
    pub user_sid: Sid,
    pub image_file_name: String,
    pub command_line: String,

    // Mutable state tracked over the process lifetime
    pub is_alive: AtomicBool,
    pub exit_status: RwLock<Option<ExitStatus>>,
}
