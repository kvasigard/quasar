//! State storage and hierarchy indexing for processes.
//!
//! This module maintains the complete timeline and hierarchy of processes observed
//! by the telemetry pipeline. It indexes processes by their operating system process
//! identifier ([`ProcessId`]) and manages PID recycling by storing generations in
//! a chronological [`ProcessTimeline`].

use std::collections::HashMap;
use thiserror::Error;

use crate::model::types::{ExitStatus, ProcessId};
use crate::model::{ParentProcess, ProcessKey, ProcessNode};

/// Errors that can occur during process tree lifecycle state transitions.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProcessTreeError {
    /// An active process is already registered under the specified PID without terminating.
    #[error("An active process already exists for PID: {0:?}")]
    ActiveProcessConflict(ProcessId),

    /// A process could not be found for the given PID and timestamp.
    #[error("No process found for PID {pid:?} at timestamp {timestamp}")]
    ProcessNotFound {
        /// Process identifier that failed lookup.
        pid: ProcessId,
        /// Query timestamp used during lookup.
        timestamp: i64,
    },

    /// The process requested for termination has already exited.
    #[error("Process with key {0:?} has already terminated")]
    AlreadyTerminated(ProcessKey),
}

/// Represents the generational lifetime history of processes sharing a single OS PID.
///
/// Windows reuses Process IDs after a process terminates. `ProcessTimeline` maintains
/// the currently active process instance for immediate $O(1)$ access and preserves
/// terminated generations in chronological order for historical telemetry correlation.
#[derive(Debug, Default)]
pub(super) struct ProcessTimeline {
    /// The currently running process instance bound to this PID.
    pub(super) active: Option<ProcessNode>,
    /// Chronologically ordered history of terminated process instances for this PID.
    pub(super) history: Vec<ProcessNode>,
}

impl ProcessTimeline {
    /// Resolves the process key whose lifetime covers the given timestamp.
    ///
    /// # Arguments
    ///
    /// * `timestamp` - The telemetry event timestamp to correlate.
    ///
    /// # Returns
    ///
    /// The [`ProcessKey`] of the active or historical process if found, or `None`.
    pub fn resolve_at_time(&self, timestamp: i64) -> Option<ProcessKey> {
        // Fast-path: Check if the active process was created prior to or at the event timestamp.
        if let Some(ref active) = self.active {
            if active.creation_timestamp() <= timestamp {
                return Some(active.key());
            }
        }

        // Search history in reverse (most recent generations first)
        for historical in self.history.iter().rev() {
            if historical.creation_timestamp() <= timestamp {
                let within_exit = match historical.exit_timestamp() {
                    Some(exit_ts) => timestamp <= exit_ts,
                    None => true,
                };
                if within_exit {
                    return Some(historical.key());
                }
            }
        }

        None
    }

    /// Finds an immutable reference to a process node matching the creation timestamp.
    ///
    /// # Arguments
    ///
    /// * `creation_timestamp` - The exact creation timestamp of the process.
    ///
    /// # Returns
    ///
    /// An immutable reference to the [`ProcessNode`] if present, or `None`.
    pub fn get(&self, creation_timestamp: i64) -> Option<&ProcessNode> {
        self.active
            .as_ref()
            .filter(|a| a.creation_timestamp() == creation_timestamp)
            .or_else(|| {
                self.history
                    .iter()
                    .find(|node| node.creation_timestamp() == creation_timestamp)
            })
    }

    /// Finds a mutable reference to a process node matching the creation timestamp.
    ///
    /// # Arguments
    ///
    /// * `creation_timestamp` - The exact creation timestamp of the process.
    ///
    /// # Returns
    ///
    /// A mutable reference to the [`ProcessNode`] if present, or `None`.
    pub fn get_mut(&mut self, creation_timestamp: i64) -> Option<&mut ProcessNode> {
        if let Some(ref mut active) = self.active {
            if active.creation_timestamp() == creation_timestamp {
                return Some(active);
            }
        }

        self.history
            .iter_mut()
            .find(|node| node.creation_timestamp() == creation_timestamp)
    }
}

/// In-memory storage and hierarchical index of all observed processes.
///
/// Stores processes grouped by their [`ProcessId`] inside a [`ProcessTimeline`].
/// This structure eliminates redundant secondary maps while facilitating $O(1)$ live-process
/// lookups and temporal resolution for recycled PIDs.
#[derive(Debug, Default)]
pub(super) struct ProcessTree {
    pub(super) processes: HashMap<ProcessId, ProcessTimeline>,
}

impl ProcessTree {
    /// Inserts a new process upon receiving a process start lifecycle event.
    ///
    /// Automatically attempts to resolve the parent [`ProcessKey`] at `process.creation_timestamp`.
    /// If resolved, establishes bidirectional parent-child links. If the parent was created before
    /// monitoring started, `parent` remains [`ParentProcess::Unresolved`] preserving `parent_pid`.
    ///
    /// # Arguments
    ///
    /// * `process` - The initialized [`ProcessNode`] to insert.
    ///
    /// # Returns
    ///
    /// The unique [`ProcessKey`] assigned to the inserted process.
    ///
    /// # Errors
    ///
    /// Returns [`ProcessTreeError::ActiveProcessConflict`] if an active, un-terminated process
    /// already occupies the same PID.
    pub fn handle_start(&mut self, mut process: ProcessNode) -> Result<ProcessKey, ProcessTreeError> {
        let child_key = process.key();
        let pid = child_key.pid;
        let creation_ts = child_key.creation_timestamp;

        let timeline = self.processes.entry(pid).or_default();
        if timeline.active.is_some() {
            return Err(ProcessTreeError::ActiveProcessConflict(pid));
        }

        // Attempt to resolve parent key at creation time
        if let Some(parent_key) = self.resolve_key(process.parent_pid(), creation_ts) {
            process.parent = ParentProcess::Resolved(parent_key);

            // Link child into parent's children collection for O(1) subtree traversal
            if let Some(parent_node) = self.get_mut(&parent_key) {
                if !parent_node.children.contains(&child_key) {
                    parent_node.children.push(child_key);
                }
            }
        }

        let timeline = self.processes.get_mut(&pid).expect("Timeline entry was inserted");
        timeline.active = Some(process);

        Ok(child_key)
    }

    /// Records a process termination event.
    ///
    /// Marks the active process for `pid` as terminated, sets its exit timestamp and status,
    /// and transitions it into the historical timeline.
    ///
    /// # Arguments
    ///
    /// * `pid` - The OS process ID of the terminating process.
    /// * `exit_timestamp` - The timestamp when the process exited.
    /// * `exit_status` - The exit code or status returned by the terminated process.
    ///
    /// # Returns
    ///
    /// The unique [`ProcessKey`] of the terminated process.
    ///
    /// # Errors
    ///
    /// Returns [`ProcessTreeError::ProcessNotFound`] if no active process is currently registered for `pid`.
    pub fn handle_exit(
        &mut self,
        pid: ProcessId,
        exit_timestamp: i64,
        exit_status: ExitStatus,
    ) -> Result<ProcessKey, ProcessTreeError> {
        let timeline = self
            .processes
            .get_mut(&pid)
            .ok_or(ProcessTreeError::ProcessNotFound {
                pid,
                timestamp: exit_timestamp,
            })?;

        let mut active = timeline
            .active
            .take()
            .ok_or(ProcessTreeError::ProcessNotFound {
                pid,
                timestamp: exit_timestamp,
            })?;

        active.exit_timestamp = Some(exit_timestamp);
        active.is_alive = false;
        active.exit_status = Some(exit_status);

        let key = active.key();
        timeline.history.push(active);

        Ok(key)
    }

    /// Resolves the composite [`ProcessKey`] for a given PID at a specific point in time.
    ///
    /// # Arguments
    ///
    /// * `pid` - The OS process ID to look up.
    /// * `timestamp` - The timestamp of the telemetry event being correlated.
    ///
    /// # Returns
    ///
    /// The matching [`ProcessKey`] if a process generation covers the timestamp, or `None`.
    pub fn resolve_key(&self, pid: ProcessId, timestamp: i64) -> Option<ProcessKey> {
        self.processes.get(&pid).and_then(|timeline| timeline.resolve_at_time(timestamp))
    }

    /// Retrieves an immutable reference to a [`ProcessNode`] using its composite key.
    ///
    /// # Arguments
    ///
    /// * `key` - The composite [`ProcessKey`] of the desired process.
    ///
    /// # Returns
    ///
    /// An immutable reference to the [`ProcessNode`] if present, or `None`.
    pub fn get(&self, key: &ProcessKey) -> Option<&ProcessNode> {
        self.processes
            .get(&key.pid)
            .and_then(|timeline| timeline.get(key.creation_timestamp))
    }

    /// Retrieves a mutable reference to a [`ProcessNode`] using its composite key.
    ///
    /// # Arguments
    ///
    /// * `key` - The composite [`ProcessKey`] of the desired process.
    ///
    /// # Returns
    ///
    /// A mutable reference to the [`ProcessNode`] if present, or `None`.
    pub fn get_mut(&mut self, key: &ProcessKey) -> Option<&mut ProcessNode> {
        self.processes
            .get_mut(&key.pid)
            .and_then(|timeline| timeline.get_mut(key.creation_timestamp))
    }

    /// Mutates a process node in-place using a scoped closure under write access.
    ///
    /// # Arguments
    ///
    /// * `key` - The composite [`ProcessKey`] of the target process.
    /// * `f` - A closure receiving a mutable reference to the [`ProcessNode`].
    ///
    /// # Returns
    ///
    /// `Some(R)` with the closure result if the process was found, or `None`.
    pub fn mutate<R>(&mut self, key: &ProcessKey, f: impl FnOnce(&mut ProcessNode) -> R) -> Option<R> {
        self.get_mut(key).map(f)
    }
}
