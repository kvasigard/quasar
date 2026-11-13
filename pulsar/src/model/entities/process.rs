//! Domain entities representing long-lived process state (`_EPROCESS`).
//!
//! In the Windows Kernel, an Executive Process (`_EPROCESS`) object combines:
//! - **Creation-time identity**: `UniqueProcessId`, `CreateTime`, `Session`, `Token` (`Sid`),
//!   and the backing image section (`SectionObject` -> [`Arc<BinaryImage>`]).
//! - **Runtime state**: Parent/child links (`InheritedFromUniqueProcessId`, `ActiveProcessLinks`),
//!   the Virtual Address Space tree (`VadRoot` -> [`ProcessAddressSpace`]), the active thread
//!   list (`ThreadListHead` -> `HashMap<ThreadId, ThreadNode>`), and termination status
//!   (`ExitTime`, `ExitStatus`).
//!

use std::collections::HashMap;
use std::sync::Arc;

use crate::model::entities::address_space::ProcessAddressSpace;
use crate::model::entities::binary::BinaryImage;
use crate::model::entities::thread::ThreadNode;
use crate::model::events::process::{ProcessEvent, ProcessEventKind};
use crate::model::security::Sid;
use crate::model::types::{ExitStatus, ProcessId, SessionId, ThreadId, UniqueProcessKey};

/// Maximum number of local (`!is_remote`) threads retained per process when `ThreadExit`
/// telemetry is not active. Remote threads (`is_remote == true`) are exempt from eviction.
pub const MAX_LOCAL_THREADS_PER_PROCESS: usize = 256;

/// Unique composite key identifying a process instance (`PID` + `Creation Time`).
///
/// Because Windows aggressively recycles Process IDs after a process exits, pairing `pid` with
/// the kernel `creation_timestamp` uniquely identifies a single `_EPROCESS` generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProcessKey {
    /// OS process identifier (`UniqueProcessId`).
    pub pid: ProcessId,
    /// High-resolution creation timestamp (`CreateTime` / QPC).
    pub creation_timestamp: i64,
}

impl ProcessKey {
    /// Creates a new [`ProcessKey`] from a process identifier and creation timestamp.
    ///
    /// # Arguments
    ///
    /// * `pid` - The OS process identifier.
    /// * `creation_timestamp` - The timestamp when the process was created.
    ///
    /// # Return values
    ///
    /// Returns a new [`ProcessKey`] instance.
    #[inline]
    pub const fn new(pid: ProcessId, creation_timestamp: i64) -> Self {
        Self {
            pid,
            creation_timestamp,
        }
    }
}

/// Represents the parent of a process, which may either be resolved in the tree or unresolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ParentProcess {
    /// Fully resolved parent process in `ProcessTree`.
    Resolved(ProcessKey),
    /// Parent PID reported by the OS when the parent started before monitoring began or exited prior to resolution.
    Unresolved(ProcessId),
}

impl ParentProcess {
    /// Returns the OS [`ProcessId`] of the parent.
    #[inline]
    pub const fn pid(&self) -> ProcessId {
        match *self {
            Self::Resolved(key) => key.pid,
            Self::Unresolved(pid) => pid,
        }
    }

    /// Returns the resolved composite [`ProcessKey`] if available.
    #[inline]
    pub const fn key(&self) -> Option<ProcessKey> {
        match *self {
            Self::Resolved(key) => Some(key),
            Self::Unresolved(_) => None,
        }
    }

    /// Returns `true` if the parent was resolved to a tracked node in `ProcessTree`.
    #[inline]
    pub const fn is_resolved(&self) -> bool {
        matches!(self, Self::Resolved(_))
    }
}

/// Long-lived state representation of a running or terminated process (`_EPROCESS`).
///
/// Fields are private to enforce lifecycle, hierarchy, and thread-table invariants.
#[derive(Debug, Clone)]
pub struct ProcessNode {
    /// Composite identity (`pid` + `creation_timestamp`).
    key: ProcessKey,
    /// Parent process reference (starts `Unresolved(parent_pid)`, upgraded via [`Self::resolve_parent`]).
    parent: ParentProcess,
    /// Kernel pointer address of the `_EPROCESS` block.
    unique_process_key: UniqueProcessKey,
    /// Windows Session ID (`SessionId`).
    session_id: SessionId,
    /// Security Identifier (`Sid`) of the primary process token.
    user_sid: Sid,
    /// Backing image path or filename reported at process creation.
    image_file_name: String,
    /// Command line invocation string.
    command_line: String,
    /// Optional shared reference to the backing executable [`BinaryImage`] in `ImageCatalog`.
    executable_image: Option<Arc<BinaryImage>>,
    /// Direct child processes spawned by this process (`O(1)` subtree traversal).
    children: Vec<ProcessKey>,
    /// Whether the process is currently active (`true`) or terminated (`false`).
    is_alive: bool,
    /// QPC timestamp when the process exited, if terminated.
    exit_timestamp: Option<i64>,
    /// OS termination status code, if terminated.
    exit_status: Option<ExitStatus>,
    /// Latched to `true` once the process's initial main thread (`ThreadStart` / `DCStart`)
    /// has been observed, allowing subsequent cross-process thread creations to be classified
    /// accurately as remote threads.
    initial_thread_seen: bool,
    /// Per-process Virtual Address Space (`_EPROCESS.VadRoot`) tracking mapped DLLs and VAD regions.
    address_space: ProcessAddressSpace,
    /// Active and correlated threads (`_EPROCESS.ThreadListHead`) keyed by [`ThreadId`].
    threads: HashMap<ThreadId, ThreadNode>,
}

impl ProcessNode {
    /// Creates a new active [`ProcessNode`] from initial telemetry data.
    ///
    /// # Arguments
    ///
    /// * `process_id` - The OS process ID.
    /// * `creation_timestamp` - Timestamp when the process was spawned.
    /// * `parent_pid` - Parent process ID reported by the OS.
    /// * `unique_process_key` - Kernel address or unique key for the `_EPROCESS` block.
    /// * `session_id` - Windows session ID.
    /// * `user_sid` - Security identifier of the user account running the process.
    /// * `image_file_name` - Binary or image file path of the process.
    /// * `command_line` - Command line invocation arguments.
    ///
    /// # Return values
    ///
    /// Returns a new [`ProcessNode`] initialized in the active (`is_alive = true`) state with an
    /// empty [`ProcessAddressSpace`] and thread table.
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

    /// Returns the composite [`ProcessKey`] (`pid` + `creation_timestamp`).
    #[inline]
    pub const fn key(&self) -> ProcessKey {
        self.key
    }

    /// Returns the OS [`ProcessId`].
    #[inline]
    pub const fn process_id(&self) -> ProcessId {
        self.key.pid
    }

    /// Returns the process creation timestamp.
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

    /// Returns a reference to the process owner's user [`Sid`].
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

    /// Returns a slice of composite keys for direct children spawned by this process.
    #[inline]
    pub fn children(&self) -> &[ProcessKey] {
        &self.children
    }

    /// Returns `true` if the process is currently active/running.
    #[inline]
    pub const fn is_alive(&self) -> bool {
        self.is_alive
    }

    /// Returns the exit timestamp if the process has terminated.
    #[inline]
    pub const fn exit_timestamp(&self) -> Option<i64> {
        self.exit_timestamp
    }

    /// Returns the process [`ExitStatus`] if terminated.
    #[inline]
    pub const fn exit_status(&self) -> Option<ExitStatus> {
        self.exit_status
    }

    // ========================================================================
    // Controlled Lifecycle & Metadata Mutators
    // ========================================================================

    /// Upgrades the parent reference to [`ParentProcess::Resolved(parent_key)`].
    #[inline]
    pub fn resolve_parent(&mut self, parent_key: ProcessKey) {
        self.parent = ParentProcess::Resolved(parent_key);
    }

    /// Registers `child_key` as a direct child of this process if not already present.
    pub fn add_child(&mut self, child_key: ProcessKey) {
        if !self.children.contains(&child_key) {
            self.children.push(child_key);
        }
    }

    /// Transitions this process into the terminated state (`is_alive = false`) with the given
    /// `exit_timestamp` and `exit_status`.
    #[inline]
    pub fn mark_exited(&mut self, exit_timestamp: i64, exit_status: ExitStatus) {
        self.is_alive = false;
        self.exit_timestamp = Some(exit_timestamp);
        self.exit_status = Some(exit_status);
    }

    /// Updates the command line string for this process.
    pub fn set_command_line(&mut self, command_line: impl Into<String>) {
        self.command_line = command_line.into();
    }

    /// Updates the image file name for this process.
    pub fn set_image_file_name(&mut self, image_file_name: impl Into<String>) {
        self.image_file_name = image_file_name.into();
    }

    // ========================================================================
    // Milestone 4: Backing Binary, Address Space, and Thread State (TODOs)
    // ========================================================================

    /// Returns a reference to the backing executable [`Arc<BinaryImage>`] if linked.
    #[inline]
    pub fn executable_image(&self) -> Option<&Arc<BinaryImage>> {
        todo!("Implement ProcessNode::executable_image")
    }

    /// Links this process to its backing [`Arc<BinaryImage>`] from `ImageCatalog`.
    #[inline]
    pub fn set_executable_image(&mut self, image: Arc<BinaryImage>) {
        todo!("Implement ProcessNode::set_executable_image")
    }

    /// Returns an immutable reference to this process's [`ProcessAddressSpace`].
    #[inline]
    pub const fn address_space(&self) -> &ProcessAddressSpace {
        todo!()
    }

    /// Returns a mutable reference to this process's [`ProcessAddressSpace`].
    #[inline]
    pub fn address_space_mut(&mut self) -> &mut ProcessAddressSpace {
        todo!("Implement ProcessNode::address_space_mut")
    }

    /// Returns `true` if the process's initial main thread has already been observed.
    #[inline]
    pub const fn initial_thread_seen(&self) -> bool {
        todo!()
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
    /// However, what if an attacker spawns a process in `CREATE_SUSPENDED` mode (`initial_thread_seen == false`),
    /// and a **third-party** injector process (`creator_pid != self.parent_pid()`) injects a remote thread?
    /// Or what if the process was enumerated at startup via `DCStart` (already running) and later
    /// receives a remote thread?
    ///
    /// Use these exact rules to determine `is_remote` and update `self.initial_thread_seen`:
    /// 1. If `!self.initial_thread_seen`:
    ///    - Set `self.initial_thread_seen = true`.
    ///    - If `creator_pid == self.process_id()` OR `creator_pid == self.parent_pid()`, this is
    ///      the legitimate initial main thread (`is_remote = false`).
    ///    - Otherwise (`creator_pid != self.process_id() && creator_pid != self.parent_pid()`),
    ///      a third-party process injected a thread before the main thread was seen (`is_remote = true`)!
    /// 2. If `self.initial_thread_seen` is *already* `true`:
    ///    - Any thread where `creator_pid != self.process_id()` is a remote thread (`is_remote = true`).
    ///    - Any thread where `creator_pid == self.process_id()` is a local thread (`is_remote = false`).
    ///
    /// # Bounded Local Thread Eviction
    ///
    /// Before inserting a **local** thread (`!is_remote`), if `self.threads.len() >= MAX_LOCAL_THREADS_PER_PROCESS`:
    /// - Find and remove the oldest **local** thread (`!t.is_remote()`) with the smallest `created_at_qpc`
    ///   (never evict a remote thread `t.is_remote() == true`!).
    pub fn register_thread(
        &mut self,
        thread_id: ThreadId,
        creator_pid: ProcessId,
        creator_key: Option<ProcessKey>,
        start_address: u64,
        created_at_qpc: i64,
    ) -> &ThreadNode {
        todo!("Implement ProcessNode::register_thread")
    }

    /// Looks up an active [`ThreadNode`] by its [`ThreadId`].
    #[inline]
    pub fn thread(&self, thread_id: ThreadId) -> Option<&ThreadNode> {
        todo!("Implement ProcessNode::thread")
    }

    /// Looks up a mutable [`ThreadNode`] by its [`ThreadId`].
    #[inline]
    pub fn thread_mut(&mut self, thread_id: ThreadId) -> Option<&mut ThreadNode> {
        todo!("Implement ProcessNode::thread_mut")
    }

    /// Removes and returns a [`ThreadNode`] upon thread termination (`ThreadExit`).
    #[inline]
    pub fn remove_thread(&mut self, thread_id: ThreadId) -> Option<ThreadNode> {
        todo!("Implement ProcessNode::remove_thread")
    }

    /// Returns the total number of tracked threads in this process.
    #[inline]
    pub fn thread_count(&self) -> usize {
        todo!("Implement ProcessNode::thread_count")
    }
}

impl TryFrom<&ProcessEvent> for ProcessNode {
    type Error = &'static str;

    /// Attempts to convert a telemetry [`ProcessEvent`] into a [`ProcessNode`].
    ///
    /// Only `Start` and `DCStart` events represent process creation.
    /// Note: For `DCStart` (processes already running when Pulsar starts), the initial main
    /// thread started in the past, so `initial_thread_seen` is immediately set to `true`.
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

    /// Attempts to convert an owned telemetry [`ProcessEvent`] into a [`ProcessNode`].
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
