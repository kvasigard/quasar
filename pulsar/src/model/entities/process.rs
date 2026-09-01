//! Domain entities representing long-lived process state.

use crate::model::security::Sid;
use crate::model::types::{ExitStatus, ProcessId, SessionId, UniqueProcessKey};

/// Unique composite key identifying a process instance (PID + Creation Time).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProcessKey {
    pub pid: ProcessId,
    pub creation_timestamp: i64,
}

impl ProcessKey {
    /// Creates a new `ProcessKey` from a process identifier and creation timestamp.
    ///
    /// # Arguments
    ///
    /// * `pid` - The OS process identifier.
    /// * `creation_timestamp` - The timestamp when the process was created.
    ///
    /// # Returns
    ///
    /// A new `ProcessKey` instance.
    pub fn new(pid: ProcessId, creation_timestamp: i64) -> Self {
        // TODO: Validate that the PID is valid and the timestamp is not in the future
        Self {
            pid,
            creation_timestamp,
        }
    }
}

/// Represents the parent of a process, which may either be resolved in the tree or unresolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ParentProcess {
    /// Fully resolved parent process in the tree.
    Resolved(ProcessKey),
    /// Parent PID reported by the OS when the process started before monitoring began or was untracked.
    Unresolved(ProcessId),
}

impl ParentProcess {
    /// Returns the OS process ID of the parent.
    #[inline]
    pub fn pid(&self) -> ProcessId {
        match *self {
            Self::Resolved(key) => key.pid,
            Self::Unresolved(pid) => pid,
        }
    }

    /// Returns the resolved composite key if available.
    #[inline]
    pub fn key(&self) -> Option<ProcessKey> {
        match *self {
            Self::Resolved(key) => Some(key),
            Self::Unresolved(_) => None,
        }
    }

    /// Returns whether the parent was successfully resolved to an existing node.
    #[inline]
    pub fn is_resolved(&self) -> bool {
        matches!(self, Self::Resolved(_))
    }
}

/// Long-lived state representation of a running or terminated process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessNode {
    // Single source of truth for process identity
    pub key: ProcessKey,

    // Single source of truth for parent process identity
    pub parent: ParentProcess,

    pub unique_process_key: UniqueProcessKey,
    pub session_id: SessionId,
    pub user_sid: Sid,
    pub image_file_name: String,
    pub command_line: String,

    // Hierarchy links
    /// Direct children spawned by this process.
    /// Maintaining this collection enables $O(1)$ subtree queries and child enumeration.
    pub children: Vec<ProcessKey>,

    // Mutable state tracked over the process lifetime (synchronized via state lock)
    pub is_alive: bool,
    pub exit_timestamp: Option<i64>,
    pub exit_status: Option<ExitStatus>,
}

impl ProcessNode {
    /// Creates a new active `ProcessNode` from initial telemetry data.
    ///
    /// # Arguments
    ///
    /// * `process_id` - The OS process ID.
    /// * `creation_timestamp` - Timestamp when the process was spawned.
    /// * `parent_pid` - Parent process ID reported by the OS.
    /// * `unique_process_key` - Kernel address or unique key for the process block.
    /// * `session_id` - Windows session ID.
    /// * `user_sid` - Security identifier of the user account running the process.
    /// * `image_file_name` - Binary or image file path of the process.
    /// * `command_line` - Command line invocation arguments.
    ///
    /// # Returns
    ///
    /// A new `ProcessNode` initialized in the active (running) state.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        process_id: ProcessId,
        creation_timestamp: i64,
        parent_pid: ProcessId,
        unique_process_key: UniqueProcessKey,
        session_id: SessionId,
        user_sid: Sid,
        image_file_name: String,
        command_line: String,
    ) -> Self {
        Self {
            key: ProcessKey::new(process_id, creation_timestamp),
            parent: ParentProcess::Unresolved(parent_pid),
            unique_process_key,
            session_id,
            user_sid,
            image_file_name,
            command_line,
            children: Vec::new(),
            is_alive: true,
            exit_timestamp: None,
            exit_status: None,
        }
    }

    /// Returns the composite process key.
    #[inline]
    pub fn key(&self) -> ProcessKey {
        self.key
    }

    /// Returns the OS process ID.
    #[inline]
    pub fn process_id(&self) -> ProcessId {
        self.key.pid
    }

    /// Returns the process creation timestamp.
    #[inline]
    pub fn creation_timestamp(&self) -> i64 {
        self.key.creation_timestamp
    }

    /// Returns the parent process representation.
    #[inline]
    pub fn parent(&self) -> ParentProcess {
        self.parent
    }

    /// Returns the parent process ID reported at spawn time.
    #[inline]
    pub fn parent_pid(&self) -> ProcessId {
        self.parent.pid()
    }

    /// Returns the resolved composite key of the parent process, if known.
    #[inline]
    pub fn parent_key(&self) -> Option<ProcessKey> {
        self.parent.key()
    }

    /// Returns the kernel unique process key / pointer.
    #[inline]
    pub fn unique_process_key(&self) -> UniqueProcessKey {
        self.unique_process_key
    }

    /// Returns the session ID.
    #[inline]
    pub fn session_id(&self) -> SessionId {
        self.session_id
    }

    /// Returns a reference to the process owner's user SID.
    #[inline]
    pub fn user_sid(&self) -> &Sid {
        &self.user_sid
    }

    /// Returns the binary image file name.
    #[inline]
    pub fn image_file_name(&self) -> &str {
        &self.image_file_name
    }

    /// Returns the process invocation command line.
    #[inline]
    pub fn command_line(&self) -> &str {
        &self.command_line
    }

    /// Returns a slice of composite keys for direct children spawned by this process.
    #[inline]
    pub fn children(&self) -> &[ProcessKey] {
        &self.children
    }

    /// Returns whether the process is currently active/running.
    #[inline]
    pub fn is_alive(&self) -> bool {
        self.is_alive
    }

    /// Returns the exit timestamp, if the process has terminated.
    #[inline]
    pub fn exit_timestamp(&self) -> Option<i64> {
        self.exit_timestamp
    }

    /// Returns the process exit status, if terminated.
    #[inline]
    pub fn exit_status(&self) -> Option<ExitStatus> {
        self.exit_status
    }

    /// Updates the command line string for this process.
    ///
    /// # Arguments
    ///
    /// * `command_line` - The updated command line string.
    pub fn set_command_line(&mut self, command_line: impl Into<String>) {
        self.command_line = command_line.into();
    }

    /// Updates the image file name for this process.
    ///
    /// # Arguments
    ///
    /// * `image_file_name` - The updated image file path or name.
    pub fn set_image_file_name(&mut self, image_file_name: impl Into<String>) {
        self.image_file_name = image_file_name.into();
    }
}

use crate::model::events::process::{ProcessEvent, ProcessEventKind};

impl TryFrom<&ProcessEvent> for ProcessNode {
    type Error = &'static str;

    /// Attempts to convert a telemetry `ProcessEvent` into a `ProcessNode`.
    ///
    /// Only `Start` and `DCStart` events represent process creation.
    fn try_from(event: &ProcessEvent) -> Result<Self, Self::Error> {
        match event.kind {
            ProcessEventKind::Start | ProcessEventKind::DCStart => Ok(ProcessNode::new(
                event.process_id,
                event.timestamp,
                event.parent_id,
                event.unique_process_key,
                event.session_id,
                event.user_sid.clone(),
                event.image_file_name.clone(),
                event.command_line.clone(),
            )),
            _ => Err("ProcessNode can only be instantiated from Start or DCStart events"),
        }
    }
}

impl TryFrom<ProcessEvent> for ProcessNode {
    type Error = &'static str;

    /// Attempts to convert an owned telemetry `ProcessEvent` into a `ProcessNode`.
    fn try_from(event: ProcessEvent) -> Result<Self, Self::Error> {
        match event.kind {
            ProcessEventKind::Start | ProcessEventKind::DCStart => Ok(ProcessNode::new(
                event.process_id,
                event.timestamp,
                event.parent_id,
                event.unique_process_key,
                event.session_id,
                event.user_sid,
                event.image_file_name,
                event.command_line,
            )),
            _ => Err("ProcessNode can only be instantiated from Start or DCStart events"),
        }
    }
}
