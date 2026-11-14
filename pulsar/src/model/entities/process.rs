//! Domain entities representing long-lived OS process state (`_EPROCESS`).
//!
//! # Architectural Role & Data Flow
//!
//! In the Windows Kernel, an Executive Process (`_EPROCESS`) object combines static creation
//! identity with dynamic runtime state:
//! - **Creation-time identity**: `UniqueProcessId` ([`ProcessId`]), `CreateTime` (paired into
//!   [`ProcessKey`] to defeat PID recycling), `SessionId` ([`SessionId`]), primary token [`Sid`],
//!   and the backing executable section (`SectionObject` -> [`Arc<BinaryImage>`]).
//! - **Runtime state**: Parent/child lineage links (`InheritedFromUniqueProcessId` -> [`ParentProcess`],
//!   `ActiveProcessLinks` -> `children`), the per-process Virtual Address Space tree
//!   (`VadRoot` -> [`ProcessAddressSpace`]), the active thread table
//!   (`ThreadListHead` -> `HashMap<ThreadId, ThreadNode>`), and termination metadata
//!   (`ExitTime`, `ExitStatus`).
//!
//! Within Quasar's pipeline, raw kernel process telemetry is decoded into a [`ProcessEvent`],
//! converted into a [`ProcessNode`] via [`TryFrom`], and indexed inside `ProcessTree`. As
//! subsequent `ImageLoad`, `ThreadStart`, and memory events arrive, listeners mutate the owning
//! [`ProcessNode`] to correlate multi-stage process injection techniques (such as
//! `CreateRemoteThread` into `LoadLibrary*` or unbacked `W -> X` shellcode regions).

use std::collections::HashMap;
use std::sync::Arc;

use crate::model::entities::address_space::ProcessAddressSpace;
use crate::model::entities::binary::BinaryImage;
use crate::model::entities::thread::ThreadNode;
use crate::model::events::process::{ProcessEvent, ProcessEventKind};
use crate::model::security::Sid;
use crate::model::types::{ExitStatus, ProcessId, SessionId, ThreadId, UniqueProcessKey};

/// Maximum number of local (`!is_remote`) threads retained per process when `ThreadExit`
/// telemetry is not active or threads churn rapidly.
///
/// Remote threads (`is_remote == true`) are exempt from capacity-based eviction so high-signal
/// cross-process injection attribution is never lost due to benign worker-thread churn.
pub const MAX_LOCAL_THREADS_PER_PROCESS: usize = 256;

/// Unique composite key identifying a specific process instance (`PID` + `Creation Time`).
///
/// # Architectural Role & Invariants
///
/// Windows aggressively reuses 32-bit Process IDs (`UniqueProcessId`) as soon as a process exits
/// and all handles to its `_EPROCESS` object are closed. Indexing state by [`ProcessId`] alone
/// would cause new processes to collide with historical telemetry from exited processes.
/// Pairing `pid` with the high-resolution `creation_timestamp` (`CreateTime` / QPC ticks) uniquely
/// identifies a single `_EPROCESS` generation across the entire lifetime of a host session.
///
/// # Thread Safety
///
/// `ProcessKey` is a plain `Copy` value type (`Send + Sync`) safe to pass across pipeline stages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProcessKey {
    /// Operating system process identifier (`UniqueProcessId`).
    pub pid: ProcessId,
    /// High-resolution creation timestamp (`CreateTime` or QPC ticks at process creation).
    pub creation_timestamp: i64,
}

impl ProcessKey {
    /// Creates a new composite [`ProcessKey`] from an OS process identifier and creation timestamp.
    ///
    /// # Arguments
    ///
    /// * `pid` - The OS process identifier (`UniqueProcessId`).
    /// * `creation_timestamp` - The high-resolution timestamp recorded when the process was created.
    ///
    /// # Returns
    ///
    /// A new [`ProcessKey`] uniquely identifying that process generation.
    #[inline]
    pub const fn new(pid: ProcessId, creation_timestamp: i64) -> Self {
        Self {
            pid,
            creation_timestamp,
        }
    }
}

/// Lineage reference to a process's parent, which may be resolved in `ProcessTree`
/// or remain an unresolved OS PID.
///
/// # Variant Semantics
///
/// When a [`ProcessNode`] is first instantiated from a [`ProcessEvent`], only the raw parent PID
/// (`InheritedFromUniqueProcessId`) is known from the ETW payload, so every node starts with
/// [`ParentProcess::Unresolved`]. When inserted into `ProcessTree`, the tree attempts to correlate
/// that parent PID against the active generation at the child's creation timestamp and upgrades
/// the link to [`ParentProcess::Resolved`] via [`ProcessNode::resolve_parent`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ParentProcess {
    /// Fully correlated parent process generation in `ProcessTree`.
    ///
    /// Produced when the parent process was alive (or present in historical timeline) at the
    /// child's creation timestamp, enabling exact `O(1)` ancestor walks immune to PID reuse.
    Resolved(ProcessKey),
    /// Unresolved parent [`ProcessId`] reported by the OS.
    ///
    /// Retained when the parent process both started and exited before Pulsar began monitoring,
    /// or when kernel PID 0 / System parent links have no corresponding tracked generation.
    Unresolved(ProcessId),
}

impl ParentProcess {
    /// Returns the OS [`ProcessId`] of the parent regardless of whether its generation key is resolved.
    ///
    /// # Returns
    ///
    /// The parent's [`ProcessId`].
    #[inline]
    pub const fn pid(&self) -> ProcessId {
        match *self {
            Self::Resolved(key) => key.pid,
            Self::Unresolved(pid) => pid,
        }
    }

    /// Returns the resolved composite [`ProcessKey`] of the parent if lineage correlation succeeded.
    ///
    /// # Returns
    ///
    /// `Some(ProcessKey)` when [`ParentProcess::Resolved`], or `None` when [`ParentProcess::Unresolved`].
    #[inline]
    pub const fn key(&self) -> Option<ProcessKey> {
        match *self {
            Self::Resolved(key) => Some(key),
            Self::Unresolved(_) => None,
        }
    }

    /// Returns `true` if the parent was resolved to a tracked generation in `ProcessTree`.
    ///
    /// # Returns
    ///
    /// `true` if [`ParentProcess::Resolved`], `false` if [`ParentProcess::Unresolved`].
    #[inline]
    pub const fn is_resolved(&self) -> bool {
        matches!(self, Self::Resolved(_))
    }
}

/// Long-lived state representation of a running or terminated OS process (`_EPROCESS`).
///
/// # Architectural Role
///
/// `ProcessNode` is the central aggregate root for per-process telemetry in Quasar. Stored inside
/// `ProcessTree`, it links:
/// 1. **Process Identity & Lineage**: PID, creation timestamp, parent/child graph links, session, and [`Sid`].
/// 2. **Backing Executable**: Shared reference to the deduplicated [`BinaryImage`] in `ImageCatalog`.
/// 3. **Virtual Address Space ([`ProcessAddressSpace`])**: Mapped PE modules (`ImageLoad`) and
///    virtual memory allocations/protections (`VadRegion`).
/// 4. **Thread Table (`HashMap<ThreadId, ThreadNode>`)**: Active threads, distinguishing normal
///    local threads (including the parent-created initial main thread) from cross-process remote
///    threads (`CreateRemoteThread` / `NtCreateThreadEx`).
///
/// # State Invariants
///
/// - **Encapsulation**: All fields are private; state transitions occur exclusively through
///   validated mutators (`resolve_parent`, `add_child`, `mark_exited`, `register_thread`).
/// - **Monotonic `initial_thread_seen` Latch**: Starts `false` for newly spawned processes
///   (`ProcessEventKind::Start`) and `true` for pre-existing rundown processes
///   (`ProcessEventKind::DCStart`). Latches to `true` on the first observed thread creation.
/// - **Remote Thread Retention**: Capacity eviction (`MAX_LOCAL_THREADS_PER_PROCESS`) only evicts
///   local threads (`!t.is_remote()`). Remote threads (`t.is_remote()`) are never evicted by
///   capacity limits so injection correlation state cannot be flushed by local thread churn.
///
/// # Thread Safety
///
/// `ProcessNode` implements `Send + Sync` (all owned fields and [`Arc<BinaryImage>`] are
/// thread-safe), allowing safe access across synchronized `ProcessTree` locks.
#[derive(Debug, Clone)]
pub struct ProcessNode {
    /// Composite identity (`pid` + `creation_timestamp`) uniquely identifying this generation.
    key: ProcessKey,
    /// Parent process reference (starts `Unresolved(parent_pid)`, upgraded via [`Self::resolve_parent`]).
    parent: ParentProcess,
    /// Kernel pointer address of the `_EPROCESS` block (`UniqueProcessKey`).
    unique_process_key: UniqueProcessKey,
    /// Windows terminal services Session ID (`SessionId`).
    session_id: SessionId,
    /// Security Identifier (`Sid`) of the primary process token.
    user_sid: Sid,
    /// Backing image path or filename reported at process creation.
    image_file_name: String,
    /// Full command-line invocation string passed to the process.
    command_line: String,
    /// Shared reference to the backing executable [`BinaryImage`] in `ImageCatalog`.
    executable_image: Option<Arc<BinaryImage>>,
    /// Direct child process generations spawned by this process (`O(1)` downward subtree traversal).
    children: Vec<ProcessKey>,
    /// Whether the process is currently active (`true`) or has terminated (`false`).
    is_alive: bool,
    /// High-resolution QPC timestamp when the process exited, if terminated.
    exit_timestamp: Option<i64>,
    /// OS termination status code (`ExitStatus`), if terminated.
    exit_status: Option<ExitStatus>,
    /// Monotonic latch set to `true` once the process's initial main thread (`ThreadStart` or
    /// `DCStart` rundown) has been observed, allowing subsequent cross-process thread creations
    /// from the parent PID to be accurately classified as remote threads.
    initial_thread_seen: bool,
    /// Per-process Virtual Address Space (`_EPROCESS.VadRoot`) tracking mapped DLLs and VAD regions.
    address_space: ProcessAddressSpace,
    /// Active and correlated threads (`_EPROCESS.ThreadListHead`) keyed by [`ThreadId`].
    threads: HashMap<ThreadId, ThreadNode>,
}

impl ProcessNode {
    /// Creates a new active [`ProcessNode`] from initial process creation telemetry.
    ///
    /// # Arguments
    ///
    /// * `process_id` - The OS process ID (`UniqueProcessId`).
    /// * `creation_timestamp` - High-resolution timestamp when the process was spawned.
    /// * `parent_pid` - Parent process ID (`InheritedFromUniqueProcessId`) reported by the OS.
    /// * `unique_process_key` - Kernel address or unique key for the `_EPROCESS` structure.
    /// * `session_id` - Windows session ID under which the process runs.
    /// * `user_sid` - Security identifier ([`Sid`]) of the user account owning the process token.
    /// * `image_file_name` - Binary path or image file name of the process executable.
    /// * `command_line` - Command-line invocation arguments.
    ///
    /// # Returns
    ///
    /// A new [`ProcessNode`] initialized in the active (`is_alive = true`) state with
    /// `ParentProcess::Unresolved(parent_pid)`, `initial_thread_seen = false`, an empty
    /// [`ProcessAddressSpace`], and an empty thread table.
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
            executable_image: None,
            children: Vec::new(),
            is_alive: true,
            exit_timestamp: None,
            exit_status: None,
            initial_thread_seen: false,
            address_space: ProcessAddressSpace::new(),
            threads: HashMap::new(),
        }
    }

    // ========================================================================
    // Identity & Lineage Accessors
    // ========================================================================

    /// Returns the composite [`ProcessKey`] (`pid` + `creation_timestamp`) for this process generation.
    #[inline]
    pub const fn key(&self) -> ProcessKey {
        self.key
    }

    /// Returns the OS [`ProcessId`] (`UniqueProcessId`).
    #[inline]
    pub const fn process_id(&self) -> ProcessId {
        self.key.pid
    }

    /// Returns the high-resolution process creation timestamp.
    #[inline]
    pub const fn creation_timestamp(&self) -> i64 {
        self.key.creation_timestamp
    }

    /// Returns the [`ParentProcess`] state (`Resolved` or `Unresolved`).
    #[inline]
    pub const fn parent(&self) -> ParentProcess {
        self.parent
    }

    /// Returns the parent [`ProcessId`] reported at spawn time.
    #[inline]
    pub const fn parent_pid(&self) -> ProcessId {
        self.parent.pid()
    }

    /// Returns the resolved composite [`ProcessKey`] of the parent process, if known.
    #[inline]
    pub const fn parent_key(&self) -> Option<ProcessKey> {
        self.parent.key()
    }

    /// Returns the kernel [`UniqueProcessKey`] (`_EPROCESS` pointer).
    #[inline]
    pub const fn unique_process_key(&self) -> UniqueProcessKey {
        self.unique_process_key
    }

    /// Returns the Windows [`SessionId`].
    #[inline]
    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }

    /// Returns a reference to the process owner's primary token [`Sid`].
    #[inline]
    pub fn user_sid(&self) -> &Sid {
        &self.user_sid
    }

    /// Returns the binary image path or file name reported for this process.
    #[inline]
    pub fn image_file_name(&self) -> &str {
        &self.image_file_name
    }

    /// Returns the process invocation command line.
    #[inline]
    pub fn command_line(&self) -> &str {
        &self.command_line
    }

    /// Returns a slice of composite keys for direct child processes spawned by this process.
    #[inline]
    pub fn children(&self) -> &[ProcessKey] {
        &self.children
    }

    /// Returns `true` if the process is currently active/running.
    #[inline]
    pub const fn is_alive(&self) -> bool {
        self.is_alive
    }

    /// Returns the exit timestamp if the process has terminated, or `None` if still alive.
    #[inline]
    pub const fn exit_timestamp(&self) -> Option<i64> {
        self.exit_timestamp
    }

    /// Returns the OS [`ExitStatus`] if the process has terminated, or `None` if still alive.
    #[inline]
    pub const fn exit_status(&self) -> Option<ExitStatus> {
        self.exit_status
    }

    // ========================================================================
    // Controlled Lifecycle & Metadata Mutators
    // ========================================================================

    /// Upgrades the parent reference from [`ParentProcess::Unresolved`] to [`ParentProcess::Resolved`].
    ///
    /// # Arguments
    ///
    /// * `parent_key` - The correlated [`ProcessKey`] of the parent generation in `ProcessTree`.
    #[inline]
    pub fn resolve_parent(&mut self, parent_key: ProcessKey) {
        self.parent = ParentProcess::Resolved(parent_key);
    }

    /// Registers `child_key` as a direct child of this process if not already present.
    ///
    /// # Arguments
    ///
    /// * `child_key` - The [`ProcessKey`] of the newly spawned child process.
    pub fn add_child(&mut self, child_key: ProcessKey) {
        if !self.children.contains(&child_key) {
            self.children.push(child_key);
        }
    }

    /// Transitions this process into the terminated state (`is_alive = false`) and records its
    /// exit metadata.
    ///
    /// # Arguments
    ///
    /// * `exit_timestamp` - High-resolution timestamp when the `ProcessStop` event occurred.
    /// * `exit_status` - OS termination code reported by the kernel.
    #[inline]
    pub fn mark_exited(&mut self, exit_timestamp: i64, exit_status: ExitStatus) {
        self.is_alive = false;
        self.exit_timestamp = Some(exit_timestamp);
        self.exit_status = Some(exit_status);
    }

    /// Updates the command-line string for this process (e.g., when enriched asynchronously).
    ///
    /// # Arguments
    ///
    /// * `command_line` - New command-line string.
    pub fn set_command_line(&mut self, command_line: impl Into<String>) {
        self.command_line = command_line.into();
    }

    /// Updates the image file name or full path for this process.
    ///
    /// # Arguments
    ///
    /// * `image_file_name` - New image file name or normalized path.
    pub fn set_image_file_name(&mut self, image_file_name: impl Into<String>) {
        self.image_file_name = image_file_name.into();
    }

    // ========================================================================
    // Backing Binary, Address Space, and Thread State
    // ========================================================================

    /// Returns a reference to the backing executable [`Arc<BinaryImage>`] if linked.
    ///
    /// # Returns
    ///
    /// `Some(&Arc<BinaryImage>)` if the primary executable image has been resolved in
    /// `ImageCatalog`, or `None` prior to enrichment.
    #[inline]
    pub fn executable_image(&self) -> Option<&Arc<BinaryImage>> {
        self.executable_image.as_ref()
    }

    /// Links this process to its backing executable [`Arc<BinaryImage>`] from `ImageCatalog`.
    ///
    /// # Arguments
    ///
    /// * `image` - Shared reference to the deduplicated [`BinaryImage`] for this process's main executable.
    #[inline]
    pub fn set_executable_image(&mut self, image: Arc<BinaryImage>) {
        self.executable_image = Some(image);
    }

    /// Returns an immutable reference to this process's [`ProcessAddressSpace`].
    ///
    /// # Returns
    ///
    /// Shared view of mapped PE images (`MappedImage`) and virtual memory regions (`VadRegion`).
    #[inline]
    pub const fn address_space(&self) -> &ProcessAddressSpace {
        &self.address_space
    }

    /// Returns a mutable reference to this process's [`ProcessAddressSpace`].
    ///
    /// # Returns
    ///
    /// Mutable view of the process's address space for recording `ImageLoad`, `ImageUnload`,
    /// `VirtualAlloc`, or `VirtualProtect` transitions.
    #[inline]
    pub fn address_space_mut(&mut self) -> &mut ProcessAddressSpace {
        &mut self.address_space
    }

    /// Returns `true` if the process's initial main thread has already been observed.
    ///
    /// # Returns
    ///
    /// `true` after the first thread registration (or immediately for `DCStart` rundown processes),
    /// `false` if the process has just been created and its main thread has not yet started.
    #[inline]
    pub const fn initial_thread_seen(&self) -> bool {
        self.initial_thread_seen
    }

    /// Registers a newly started thread inside this process and returns a reference to the
    /// inserted [`ThreadNode`].
    ///
    /// # Initial Thread vs. Remote Thread Classification (`is_remote`)
    ///
    /// When Windows creates a new process (`NtCreateUserProcess`), the parent process (`creator_pid`)
    /// creates the child process's very first thread (`creator_pid != self.process_id()`) before
    /// the child process has executed a single instruction.
    ///
    /// However, if an attacker spawns a process in `CREATE_SUSPENDED` mode (`initial_thread_seen == false`)
    /// and a **third-party** process (`creator_pid != self.parent_pid()`) injects a remote thread,
    /// or if the parent injects a *second* cross-process thread after the initial thread has
    /// already started (`initial_thread_seen == true`), that thread must be flagged as remote:
    ///
    /// 1. **When `!self.initial_thread_seen`**:
    ///    - Latches `self.initial_thread_seen = true`.
    ///    - If `creator_pid == self.process_id()` or `creator_pid == self.parent_pid()`, the thread
    ///      is the legitimate initial main thread (`is_remote = false`).
    ///    - Otherwise (`creator_pid != self.process_id() && creator_pid != self.parent_pid()`), a
    ///      third-party process injected a thread prior to main-thread start (`is_remote = true`).
    /// 2. **When `self.initial_thread_seen` is already `true`**:
    ///    - Any thread with `creator_pid != self.process_id()` is a remote thread (`is_remote = true`).
    ///    - Any thread with `creator_pid == self.process_id()` is a local worker thread (`is_remote = false`).
    ///
    /// # Bounded Local Thread Eviction
    ///
    /// Before inserting a new **local** thread (`!is_remote`), if
    /// `self.threads.len() >= MAX_LOCAL_THREADS_PER_PROCESS`, the oldest local thread
    /// (`!t.is_remote()`) with the minimum `created_at_qpc` is evicted. Remote threads
    /// (`t.is_remote() == true`) are never evicted by capacity limits.
    ///
    /// # Arguments
    ///
    /// * `thread_id` - OS-assigned identifier (`TThreadId`) of the newly created thread.
    /// * `creator_pid` - OS [`ProcessId`] of the actor process that issued the thread-creation syscall.
    /// * `creator_key` - Resolved [`ProcessKey`] of the creator process in `ProcessTree`, if known.
    /// * `start_address` - User-mode entry point (`Win32StartAddr`) where thread execution begins.
    /// * `created_at_qpc` - High-resolution QPC timestamp of the `ThreadStart` event.
    ///
    /// # Returns
    ///
    /// An immutable reference to the newly inserted [`ThreadNode`] inside this process's thread table.
    pub fn register_thread(
        &mut self,
        thread_id: ThreadId,
        creator_pid: ProcessId,
        creator_key: Option<ProcessKey>,
        start_address: u64,
        created_at_qpc: i64,
    ) -> &ThreadNode {
        // Determine whether this thread was created across a process boundary.
        // During normal Win32 process creation (`NtCreateUserProcess`), the parent process
        // creates the child's very first thread before the child executes any code. Once that
        // initial thread is observed (`initial_thread_seen == true`), any subsequent thread
        // created by the parent (or any other external PID) is a true remote thread injection.
        let is_remote = if !self.initial_thread_seen {
            self.initial_thread_seen = true;
            creator_pid != self.process_id() && creator_pid != self.parent_pid()
        } else {
            creator_pid != self.process_id()
        };

        // Bound memory growth from high-churn local worker threads when `ThreadExit` events are
        // disabled or missed. Remote threads are intentionally excluded from eviction candidates
        // so pending injection indicators (`pending_loader_export`, `alerted_shellcode`) cannot
        // be flushed by noisy local thread creation.
        if !is_remote
            && !self.threads.contains_key(&thread_id)
            && self.threads.len() >= MAX_LOCAL_THREADS_PER_PROCESS
            && let Some(oldest_local_tid) = self
                .threads
                .values()
                .filter(|t| !t.is_remote())
                .min_by_key(|t| t.created_at_qpc())
                .map(|t| t.thread_id())
        {
            self.threads.remove(&oldest_local_tid);
        }

        let node = ThreadNode::new(
            thread_id,
            creator_pid,
            creator_key,
            is_remote,
            start_address,
            created_at_qpc,
        );

        // Use `entry(...).insert_entry(...)` to insert and return a reference to the stored
        // `ThreadNode` in a single hash probe without a second lookup.
        self.threads.entry(thread_id).insert_entry(node).into_mut()
    }

    /// Looks up an active [`ThreadNode`] by its [`ThreadId`].
    ///
    /// # Arguments
    ///
    /// * `thread_id` - The OS [`ThreadId`] to query.
    ///
    /// # Returns
    ///
    /// `Some(&ThreadNode)` if the thread is tracked in this process, or `None` otherwise.
    #[inline]
    pub fn thread(&self, thread_id: ThreadId) -> Option<&ThreadNode> {
        self.threads.get(&thread_id)
    }

    /// Looks up a mutable [`ThreadNode`] by its [`ThreadId`].
    ///
    /// # Arguments
    ///
    /// * `thread_id` - The OS [`ThreadId`] to query.
    ///
    /// # Returns
    ///
    /// `Some(&mut ThreadNode)` if the thread is tracked in this process, or `None` otherwise.
    #[inline]
    pub fn thread_mut(&mut self, thread_id: ThreadId) -> Option<&mut ThreadNode> {
        self.threads.get_mut(&thread_id)
    }

    /// Removes and returns a [`ThreadNode`] upon thread termination (`ThreadExit`).
    ///
    /// # Arguments
    ///
    /// * `thread_id` - The OS [`ThreadId`] of the terminating thread.
    ///
    /// # Returns
    ///
    /// `Some(ThreadNode)` if the thread was present and removed, or `None` if it was not tracked.
    #[inline]
    pub fn remove_thread(&mut self, thread_id: ThreadId) -> Option<ThreadNode> {
        self.threads.remove(&thread_id)
    }

    /// Returns the total number of currently tracked threads (both local and remote) in this process.
    ///
    /// # Returns
    ///
    /// Count of [`ThreadNode`] entries in the process's thread table.
    #[inline]
    pub fn thread_count(&self) -> usize {
        self.threads.len()
    }
}

impl TryFrom<&ProcessEvent> for ProcessNode {
    type Error = &'static str;

    /// Attempts to convert a borrowed telemetry [`ProcessEvent`] into a [`ProcessNode`].
    ///
    /// # Arguments
    ///
    /// * `event` - Borrowed [`ProcessEvent`] decoded from kernel ETW telemetry.
    ///
    /// # Returns
    ///
    /// A newly initialized [`ProcessNode`]. For `DCStart` rundown events (processes that were
    /// already running when Pulsar started), `initial_thread_seen` is immediately latched to
    /// `true` because the process's main thread started prior to telemetry collection.
    ///
    /// # Errors
    ///
    /// Returns `Err` if `event.kind` is neither [`ProcessEventKind::Start`] nor
    /// [`ProcessEventKind::DCStart`] (e.g., `End`, `DCEnd`, or `Defunct`).
    fn try_from(event: &ProcessEvent) -> Result<Self, Self::Error> {
        match event.kind {
            ProcessEventKind::Start | ProcessEventKind::DCStart => {
                let mut node = ProcessNode::new(
                    event.process_id,
                    event.timestamp,
                    event.parent_id,
                    event.unique_process_key,
                    event.session_id,
                    event.user_sid.clone(),
                    event.image_file_name.clone(),
                    event.command_line.clone(),
                );
                // Rundown (`DCStart`) processes were already executing before the ETW session
                // started, so their initial main thread has already run; any future cross-process
                // thread creation targeting this process (even from its parent) is remote.
                if event.kind == ProcessEventKind::DCStart {
                    node.initial_thread_seen = true;
                }
                Ok(node)
            }
            _ => Err("ProcessNode can only be instantiated from Start or DCStart events"),
        }
    }
}

impl TryFrom<ProcessEvent> for ProcessNode {
    type Error = &'static str;

    /// Attempts to convert an owned telemetry [`ProcessEvent`] into a [`ProcessNode`] without
    /// cloning string or [`Sid`] allocations.
    ///
    /// # Arguments
    ///
    /// * `event` - Owned [`ProcessEvent`] decoded from kernel ETW telemetry.
    ///
    /// # Returns
    ///
    /// A newly initialized [`ProcessNode`], with `initial_thread_seen` latched to `true` when
    /// `event.kind == ProcessEventKind::DCStart`.
    ///
    /// # Errors
    ///
    /// Returns `Err` if `event.kind` is neither [`ProcessEventKind::Start`] nor
    /// [`ProcessEventKind::DCStart`].
    fn try_from(event: ProcessEvent) -> Result<Self, Self::Error> {
        match event.kind {
            ProcessEventKind::Start | ProcessEventKind::DCStart => {
                let is_dc_start = event.kind == ProcessEventKind::DCStart;
                let mut node = ProcessNode::new(
                    event.process_id,
                    event.timestamp,
                    event.parent_id,
                    event.unique_process_key,
                    event.session_id,
                    event.user_sid,
                    event.image_file_name,
                    event.command_line,
                );
                if is_dc_start {
                    node.initial_thread_seen = true;
                }
                Ok(node)
            }
            _ => Err("ProcessNode can only be instantiated from Start or DCStart events"),
        }
    }
}

// ============================================================================
// Unit Test Suite
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enrichment::pe::TrackedExport;
    use crate::model::entities::address_space::MappedImage;

    fn dummy_process(pid: u32, parent_pid: u32) -> ProcessNode {
        ProcessNode::new(
            ProcessId(pid),
            10_000,
            ProcessId(parent_pid),
            UniqueProcessKey(0xFFFF_8000_0000_1000),
            SessionId(1),
            Sid("S-1-5-18".to_string()),
            "C:\\Windows\\System32\\svchost.exe".to_string(),
            "svchost.exe -k netsvcs".to_string(),
        )
    }

    #[test]
    fn test_executable_image_and_address_space_integration() {
        let mut proc = dummy_process(1200, 600);
        assert!(proc.executable_image().is_none());

        let exe_bin = Arc::new(BinaryImage::new("C:\\Windows\\System32\\svchost.exe"));
        proc.set_executable_image(Arc::clone(&exe_bin));
        assert_eq!(
            proc.executable_image().map(|b| b.file_name()),
            Some("svchost.exe")
        );

        // Map ntdll into the process's address space
        let ntdll_bin = Arc::new(BinaryImage::new("C:\\Windows\\System32\\ntdll.dll"));
        proc.address_space_mut().insert_image(MappedImage::new(
            0x7FFB_0000_0000,
            0x10000,
            10_100,
            ntdll_bin,
        ));

        let found = proc
            .address_space()
            .find_image_at(0x7FFB_0000_5000)
            .expect("ntdll should be mapped in process address space");
        assert_eq!(found.image().file_name(), "ntdll.dll");
    }

    #[test]
    fn test_initial_thread_by_parent_is_not_remote_but_second_is_remote() {
        // Process 2000 spawned by Parent 1000
        let mut proc = dummy_process(2000, 1000);
        assert!(!proc.initial_thread_seen());

        // 1. Parent (PID 1000) creates the very first thread (TID 2004) during CreateProcessW
        let t1 = proc.register_thread(ThreadId(2004), ProcessId(1000), None, 0x7FF6_0000_1000, 100);
        assert!(
            !t1.is_remote(),
            "First thread created by parent_pid must be classified as local initial thread"
        );
        assert!(proc.initial_thread_seen());

        // 2. Process 2000 spawns its own local worker thread (TID 2008)
        let t2 = proc.register_thread(ThreadId(2008), ProcessId(2000), None, 0x7FF6_0000_2000, 200);
        assert!(!t2.is_remote(), "Self-created thread must not be remote");

        // 3. Later, Parent (PID 1000) or another process (PID 666) creates a second cross-process thread (TID 9999)
        let t3 = proc.register_thread(
            ThreadId(9999),
            ProcessId(1000),
            Some(ProcessKey::new(ProcessId(1000), 5_000)),
            0x7FFB_1234_0000,
            300,
        );
        assert!(
            t3.is_remote(),
            "Cross-process thread created after initial_thread_seen must be classified as remote"
        );

        // Mutate the remote thread via thread_mut to arm a loader export
        let t3_mut = proc.thread_mut(ThreadId(9999)).expect("Thread 9999 exists");
        t3_mut.set_pending_loader_export(TrackedExport::LoadLibraryW);
        assert_eq!(
            proc.thread(ThreadId(9999))
                .and_then(|t| t.pending_loader_export()),
            Some(TrackedExport::LoadLibraryW)
        );
    }

    #[test]
    fn test_third_party_injection_before_initial_thread_is_still_remote() {
        // Process 2000 spawned by Parent 1000, but PID 666 injects before main thread starts
        let mut proc = dummy_process(2000, 1000);

        let injected = proc.register_thread(
            ThreadId(3333),
            ProcessId(666), // Neither self (2000) nor parent (1000)!
            None,
            0x0000_0200_1000_0000,
            150,
        );
        assert!(
            injected.is_remote(),
            "Thread created by third-party PID != parent_pid must be flagged as remote even if first"
        );
    }

    #[test]
    fn test_bounded_local_thread_eviction_never_evicts_remote_threads() {
        let mut proc = dummy_process(4000, 1000);

        // 1. Register initial thread (local, created at QPC = 10)
        proc.register_thread(ThreadId(1), ProcessId(1000), None, 0x1000, 10);

        // 2. Register an early remote thread at QPC = 20 (oldest after TID 1, but remote!)
        proc.register_thread(ThreadId(666), ProcessId(9999), None, 0x2000, 20);
        assert!(proc.thread(ThreadId(666)).unwrap().is_remote());

        // 3. Fill up local threads up to MAX_LOCAL_THREADS_PER_PROCESS + 5
        for i in 0..(MAX_LOCAL_THREADS_PER_PROCESS as u32 + 5) {
            let tid = ThreadId(1000 + i);
            let qpc = 100 + i as i64;
            proc.register_thread(tid, ProcessId(4000), None, 0x3000, qpc);
        }

        // Verify total thread count stays bounded and the remote thread (TID 666) was NEVER evicted
        assert_eq!(proc.thread_count(), MAX_LOCAL_THREADS_PER_PROCESS);
        assert!(
            proc.thread(ThreadId(666)).is_some(),
            "Remote thread must never be evicted by local thread churn"
        );
        // Oldest local thread (TID 1 at QPC = 10) should have been evicted first
        assert!(
            proc.thread(ThreadId(1)).is_none(),
            "Oldest local thread should be evicted when capacity is exceeded"
        );
    }
}
