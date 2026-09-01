//! System state structure
//!
//! This module maintains the system state as observed by telemetry events gathered
//! across sensors.
//!
//! The [`SystemState`] structure is intended to be accessed across the `pulsar` crate
//! to correlate telemetry, navigate process lineages, and evaluate detection rules.

use std::sync::{LazyLock, RwLock};

mod process_tree;
use crate::state::process_tree::ProcessTree;
pub(crate) use crate::state::process_tree::ProcessTreeError;

use crate::model::types::{ExitStatus, ProcessId};
use crate::model::{ProcessKey, ProcessNode};

pub(crate) static STATE: LazyLock<SystemState> = LazyLock::new(SystemState::default);

/// Returns a reference to the global `SystemState` singleton.
///
/// # Returns
///
/// A static reference to the shared [`SystemState`].
#[inline]
pub(crate) fn system_state() -> &'static SystemState {
    &STATE
}

/// Central state manager tracking processes and system context.
pub(crate) struct SystemState {
    process_tree: RwLock<ProcessTree>,
}

impl Default for SystemState {
    fn default() -> Self {
        Self::new()
    }
}

impl SystemState {
    /// Creates a new, empty `SystemState` instance.
    ///
    /// # Returns
    ///
    /// An initialized [`SystemState`] with an empty process tree.
    pub fn new() -> Self {
        SystemState {
            process_tree: RwLock::new(ProcessTree::default()),
        }
    }

    /// Handles a process start lifecycle event.
    ///
    /// Ingests a new [`ProcessNode`] into the process tree, automatically resolving its
    /// parent process identity at `process.creation_timestamp` and linking them bidirectionally.
    ///
    /// # Arguments
    ///
    /// * `process` - The initialized [`ProcessNode`] representing the spawned process.
    ///
    /// # Returns
    ///
    /// The unique [`ProcessKey`] assigned to the started process.
    ///
    /// # Errors
    ///
    /// Returns [`ProcessTreeError::ActiveProcessConflict`] if an active process already exists for the PID.
    pub fn on_process_start(&self, process: ProcessNode) -> Result<ProcessKey, ProcessTreeError> {
        let mut tree = self
            .process_tree
            .write()
            .expect("SystemState process_tree lock poisoned");
        tree.handle_start(process)
    }

    /// Handles a process exit lifecycle event.
    ///
    /// Marks the active process corresponding to `pid` as terminated, sets its exit timestamp and status,
    /// and moves it into historical storage.
    ///
    /// # Arguments
    ///
    /// * `pid` - The OS process identifier of the exiting process.
    /// * `exit_timestamp` - The timestamp when the process exited.
    /// * `exit_status` - The termination status code of the process.
    ///
    /// # Returns
    ///
    /// The unique [`ProcessKey`] of the terminated process.
    ///
    /// # Errors
    ///
    /// Returns [`ProcessTreeError::ProcessNotFound`] if no active process is currently registered for `pid`.
    pub fn on_process_exit(
        &self,
        pid: ProcessId,
        exit_timestamp: i64,
        exit_status: ExitStatus,
    ) -> Result<ProcessKey, ProcessTreeError> {
        let mut tree = self
            .process_tree
            .write()
            .expect("SystemState process_tree lock poisoned");
        tree.handle_exit(pid, exit_timestamp, exit_status)
    }

    /// Resolves the [`ProcessKey`] for a given PID at a specific point in time.
    ///
    /// # Arguments
    ///
    /// * `pid` - The OS process ID to look up.
    /// * `timestamp` - The telemetry event timestamp being correlated.
    ///
    /// # Returns
    ///
    /// `Some(ProcessKey)` if a process lifetime covers the timestamp, or `None`.
    pub fn resolve_process_key(&self, pid: ProcessId, timestamp: i64) -> Option<ProcessKey> {
        let tree = self
            .process_tree
            .read()
            .expect("SystemState process_tree lock poisoned");
        tree.resolve_key(pid, timestamp)
    }

    /// Reads a process node within a scoped closure under a read lock.
    ///
    /// Holds the internal read lock only for the duration of the closure execution.
    ///
    /// # Arguments
    ///
    /// * `key` - The composite [`ProcessKey`] of the process to read.
    /// * `f` - A closure that receives an immutable reference to the [`ProcessNode`].
    ///
    /// # Returns
    ///
    /// `Some(R)` with the return value of `f` if the process exists, or `None`.
    pub fn read_process<R>(
        &self,
        key: &ProcessKey,
        f: impl FnOnce(&ProcessNode) -> R,
    ) -> Option<R> {
        let tree = self
            .process_tree
            .read()
            .expect("SystemState process_tree lock poisoned");
        tree.get(key).map(f)
    }

    /// Mutates a process node within a scoped closure under a write lock.
    ///
    /// # Arguments
    ///
    /// * `key` - The composite [`ProcessKey`] of the target process.
    /// * `f` - A closure receiving a mutable reference to the [`ProcessNode`].
    ///
    /// # Returns
    ///
    /// `Some(R)` with the return value of `f` if the process exists, or `None`.
    pub fn mutate_process<R>(
        &self,
        key: &ProcessKey,
        f: impl FnOnce(&mut ProcessNode) -> R,
    ) -> Option<R> {
        let mut tree = self
            .process_tree
            .write()
            .expect("SystemState process_tree lock poisoned");
        tree.mutate(key, f)
    }

    /// Retrieves a detached, immutable snapshot clone of a process node.
    ///
    /// This allows passing process metadata across asynchronous tasks or thread boundaries
    /// without holding internal locks.
    ///
    /// # Arguments
    ///
    /// * `key` - The composite [`ProcessKey`] of the desired process.
    ///
    /// # Returns
    ///
    /// `Some(ProcessNode)` if the process exists, or `None`.
    pub fn get_process_snapshot(&self, key: &ProcessKey) -> Option<ProcessNode> {
        let tree = self
            .process_tree
            .read()
            .expect("SystemState process_tree lock poisoned");
        tree.get(key).cloned()
    }

    /// Iterates through all immediate children of a parent process.
    ///
    /// # Arguments
    ///
    /// * `parent_key` - The composite [`ProcessKey`] of the parent process.
    /// * `f` - A closure invoked with an immutable reference to each child [`ProcessNode`].
    pub fn for_each_child(&self, parent_key: &ProcessKey, mut f: impl FnMut(&ProcessNode)) {
        let tree = self
            .process_tree
            .read()
            .expect("SystemState process_tree lock poisoned");

        if let Some(parent) = tree.get(parent_key) {
            for child_key in &parent.children {
                if let Some(child) = tree.get(child_key) {
                    f(child);
                }
            }
        }
    }

    /// Traverses upward through the process ancestry starting from `start_key`.
    ///
    /// Invokes `f` on each ancestor node until reaching the root or when `f` returns `false`.
    ///
    /// # Arguments
    ///
    /// * `start_key` - The composite [`ProcessKey`] from which to start walking ancestors.
    /// * `f` - A predicate closure invoked for each ancestor [`ProcessNode`]. Return `true` to continue traversal or `false` to halt.
    pub fn walk_ancestors(&self, start_key: &ProcessKey, mut f: impl FnMut(&ProcessNode) -> bool) {
        let tree = self
            .process_tree
            .read()
            .expect("SystemState process_tree lock poisoned");

        let mut curr_key = Some(*start_key);
        while let Some(key) = curr_key {
            if let Some(node) = tree.get(&key) {
                if !f(node) {
                    break;
                }
                curr_key = node.parent_key();
            } else {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::model::{ExitStatus, ProcessId, ProcessNode, SessionId, Sid, UniqueProcessKey};

    use super::*;

    fn create_dummy_sid() -> Sid {
        let mut bytes = vec![1u8, 5, 0, 0, 0, 0, 0, 5];
        bytes.extend_from_slice(&21u32.to_ne_bytes());
        bytes.extend_from_slice(&100u32.to_ne_bytes());
        bytes.extend_from_slice(&200u32.to_ne_bytes());
        bytes.extend_from_slice(&300u32.to_ne_bytes());
        bytes.extend_from_slice(&500u32.to_ne_bytes());
        Sid::try_from(bytes.as_slice()).expect("Invalid SID")
    }

    fn create_test_process(
        pid: u32,
        parent_pid: u32,
        creation_ts: i64,
        image: &str,
    ) -> ProcessNode {
        ProcessNode::new(
            ProcessId(pid),
            creation_ts,
            ProcessId(parent_pid),
            UniqueProcessKey(pid as usize * 1000),
            SessionId(1),
            create_dummy_sid(),
            image.to_string(),
            format!("{image} --arg"),
        )
    }

    /// Verifies process creation, initial active state, clean exit transition, and historical record retention.
    #[test]
    fn test_process_lifecycle_start_and_exit() {
        let state = SystemState::new();
        let proc_a = create_test_process(1234, 4, 1_000, "cmd.exe");

        // Start process
        let key_a = state
            .on_process_start(proc_a)
            .expect("Start should succeed");
        assert_eq!(key_a.pid, ProcessId(1234));
        assert_eq!(key_a.creation_timestamp, 1_000);

        // Verify active state via scoped read using .is_alive() getter
        let is_alive = state
            .read_process(&key_a, |p| p.is_alive())
            .expect("Process must exist");
        assert!(is_alive);

        // Terminate process
        let exit_key = state
            .on_process_exit(ProcessId(1234), 2_000, ExitStatus::Success)
            .expect("Exit should succeed");
        assert_eq!(exit_key, key_a);

        // Verify terminated state
        let (is_alive, exit_ts, exit_status) = state
            .read_process(&key_a, |p| {
                (p.is_alive(), p.exit_timestamp(), p.exit_status())
            })
            .expect("Process must still exist in history");
        assert!(!is_alive);
        assert_eq!(exit_ts, Some(2_000));
        assert_eq!(exit_status, Some(ExitStatus::Success));
    }

    /// Verifies mutating an existing process and capturing a detached snapshot.
    #[test]
    fn test_process_mutation_and_snapshot() {
        let state = SystemState::new();
        let proc_a = create_test_process(4444, 4, 1_000, "original.exe");
        let key_a = state.on_process_start(proc_a).expect("Start succeeds");

        // Mutate process fields under write lock
        let updated = state.mutate_process(&key_a, |p| {
            p.set_command_line("original.exe --injected-arg");
            p.set_image_file_name("renamed.exe");
            true
        });
        assert_eq!(updated, Some(true));

        // Read snapshot
        let snapshot = state
            .get_process_snapshot(&key_a)
            .expect("Snapshot must exist");
        assert_eq!(snapshot.image_file_name(), "renamed.exe");
        assert_eq!(snapshot.command_line(), "original.exe --injected-arg");
        assert!(snapshot.is_alive());
    }

    /// Verifies that multiple process generations sharing the same PID are disambiguated and resolved accurately using event timestamps.
    #[test]
    fn test_pid_recycling_and_temporal_resolution() {
        let state = SystemState::new();

        // Process Generation 1 on PID 5000 (starts at 1000, exits at 2000)
        let proc_gen1 = create_test_process(5000, 4, 1_000, "proc1.exe");
        let key_gen1 = state.on_process_start(proc_gen1).expect("Gen 1 start");
        state
            .on_process_exit(ProcessId(5000), 2_000, ExitStatus::Success)
            .expect("Gen 1 exit");

        // Process Generation 2 on recycled PID 5000 (starts at 3000, still running)
        let proc_gen2 = create_test_process(5000, 4, 3_000, "proc2.exe");
        let key_gen2 = state.on_process_start(proc_gen2).expect("Gen 2 start");

        // Correlate event that occurred during Generation 1 (ts = 1500)
        let resolved_gen1 = state
            .resolve_process_key(ProcessId(5000), 1_500)
            .expect("Should resolve Gen 1");
        assert_eq!(resolved_gen1, key_gen1);

        // Correlate event that occurred during Generation 2 (ts = 3500)
        let resolved_gen2 = state
            .resolve_process_key(ProcessId(5000), 3_500)
            .expect("Should resolve Gen 2");
        assert_eq!(resolved_gen2, key_gen2);

        // Verify images for both generations
        let name_gen1 = state
            .read_process(&resolved_gen1, |p| p.image_file_name().to_string())
            .unwrap();
        let name_gen2 = state
            .read_process(&resolved_gen2, |p| p.image_file_name().to_string())
            .unwrap();
        assert_eq!(name_gen1, "proc1.exe");
        assert_eq!(name_gen2, "proc2.exe");
    }

    /// Verifies automatic parent key resolution, child node linking, and upward ancestor tree traversal.
    #[test]
    fn test_parent_child_hierarchy_and_walking() {
        let state = SystemState::new();

        // Spawn Parent (PID 100)
        let parent = create_test_process(100, 4, 1_000, "explorer.exe");
        let parent_key = state.on_process_start(parent).expect("Parent start");

        // Spawn Child 1 (PID 200)
        let child1 = create_test_process(200, 100, 1_200, "cmd.exe");
        let child1_key = state.on_process_start(child1).expect("Child 1 start");

        // Spawn Child 2 (PID 300)
        let child2 = create_test_process(300, 100, 1_300, "powershell.exe");
        let child2_key = state.on_process_start(child2).expect("Child 2 start");

        // Verify parent has both children linked
        let mut children_found = Vec::new();
        state.for_each_child(&parent_key, |child| {
            children_found.push(child.process_id());
        });
        assert_eq!(children_found, vec![ProcessId(200), ProcessId(300)]);

        // Verify child1's parent_key is resolved
        let resolved_parent = state
            .read_process(&child1_key, |p| p.parent_key())
            .flatten()
            .expect("Parent key should be resolved");
        assert_eq!(resolved_parent, parent_key);

        // Walk ancestors from child2
        let mut ancestors = Vec::new();
        state.walk_ancestors(&child2_key, |node| {
            ancestors.push(node.process_id());
            true
        });
        assert_eq!(ancestors, vec![ProcessId(300), ProcessId(100)]);
    }

    /// Verifies that registering a new active process on a PID that has not yet terminated returns an ActiveProcessConflict error.
    #[test]
    fn test_active_process_conflict_error() {
        let state = SystemState::new();
        let proc1 = create_test_process(8888, 4, 1_000, "app.exe");
        state.on_process_start(proc1).expect("First start succeeds");

        // Starting another process on the same PID without exiting the first returns error
        let proc2 = create_test_process(8888, 4, 2_000, "app2.exe");
        let err = state.on_process_start(proc2).unwrap_err();
        assert_eq!(
            err,
            ProcessTreeError::ActiveProcessConflict(ProcessId(8888))
        );
    }
}
