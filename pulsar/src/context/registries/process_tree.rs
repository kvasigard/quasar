//! Concurrent, lock-striped process graph and two-tier lookup registry.

use std::sync::Arc;
use dashmap::DashMap;

use crate::context::identity::ProcessKey;
use crate::context::models::process::ProcessContext;

/// Concurrent graph and relational storage container for process lifecycles.
///
/// Features:
/// - `active_pids`: Fast O(1) lock-striped table mapping raw OS PIDs to synthetic `ProcessKey`s.
///   Only holds currently running processes so recycled PIDs never collide.
/// - `processes`: The historical and active context arena. Holds active AND retained/tombstone
///   processes for deep forensic lineage lookups.
pub struct ProcessTree {
    /// Maps active OS PID to its current synthetic ProcessKey.
    active_pids: DashMap<u32, ProcessKey>,
    /// Global process store mapping `ProcessKey` to `Arc<ProcessContext>`.
    processes: DashMap<ProcessKey, Arc<ProcessContext>>,
}

impl ProcessTree {
    /// Creates a new empty `ProcessTree`.
    ///
    /// # Returns
    ///
    /// An empty, initialized [`ProcessTree`].
    pub fn new() -> Self {
        Self {
            active_pids: DashMap::new(),
            processes: DashMap::new(),
        }
    }

    /// Inserts a new process, automatically resolves parent lineage via active PIDs, and activates PID routing.
    ///
    /// # Arguments
    ///
    /// * `context` - The initial process context.
    ///
    /// # Returns
    ///
    /// An `Arc<ProcessContext>` stored in the process arena.
    pub fn insert_process(&self, mut context: ProcessContext) -> Arc<ProcessContext> {
        let pid = context.pid;
        let parent_pid = context.parent_pid;
        let key = context.key;

        // Fast resolution of parent's synthetic key via active PID map
        let resolved_parent_key = if parent_pid != 0 {
            self.active_pids.get(&parent_pid).map(|entry| *entry.value())
        } else {
            None
        };

        context.parent_key = resolved_parent_key;
        let context_arc = Arc::new(context);

        // Store into global arena
        self.processes.insert(key, Arc::clone(&context_arc));

        // Link under parent's child list if parent exists in arena
        if let Some(parent_k) = resolved_parent_key
            && let Some(parent_ctx) = self.processes.get(&parent_k)
        {
            parent_ctx.child_keys.write().insert(key);
        }

        // Activate PID routing for subsequent telemetry events
        self.active_pids.insert(pid, key);

        log::trace!(
            target: "system_tree",
            "Inserted process: PID {pid}, Key {key}, Parent PID {parent_pid}, Parent Key {resolved_parent_key:?}"
        );

        context_arc
    }

    /// Marks a process as terminated, unmaps its PID immediately from the active index, and records termination.
    ///
    /// # Arguments
    ///
    /// * `pid` - Operating system Process ID.
    /// * `exit_status` - Win32 exit status code.
    /// * `timestamp` - Termination timestamp.
    ///
    /// # Returns
    ///
    /// `Some(Arc<ProcessContext>)` if the process was active, otherwise `None`.
    pub fn exit_process(
        &self,
        pid: u32,
        exit_status: u32,
        timestamp: i64,
    ) -> Option<Arc<ProcessContext>> {
        // Remove from active PID routing so recycled PIDs immediately hit an empty slot
        let (_, key) = self.active_pids.remove(&pid)?;

        if let Some(context_entry) = self.processes.get(&key) {
            let context = context_entry.value();
            context.mark_terminated(exit_status, timestamp);

            log::debug!(
                target: "system_tree",
                "Process exited: PID {pid}, Key {key}, ExitStatus {exit_status:#x}"
            );

            return Some(Arc::clone(context));
        }

        None
    }

    /// Resolves an active process context using its current OS PID.
    ///
    /// # Arguments
    ///
    /// * `pid` - Operating system Process ID.
    ///
    /// # Returns
    ///
    /// `Some(Arc<ProcessContext>)` if the PID is currently running, otherwise `None`.
    #[inline]
    pub fn get_by_pid(&self, pid: u32) -> Option<Arc<ProcessContext>> {
        let key_ref = self.active_pids.get(&pid)?;
        self.get_by_key(*key_ref.value())
    }

    /// Resolves an active process context using its OS PID, or creates a placeholder context if missing.
    ///
    /// # Arguments
    ///
    /// * `pid` - Operating system Process ID.
    /// * `timestamp` - Current telemetry timestamp.
    ///
    /// # Returns
    ///
    /// An `Arc<ProcessContext>` stored in the process tree.
    pub fn get_or_create_by_pid(&self, pid: u32, timestamp: i64) -> Arc<ProcessContext> {
        match self.active_pids.entry(pid) {
            dashmap::mapref::entry::Entry::Occupied(mut occupied) => {
                let key = *occupied.get();
                if let Some(proc) = self.get_by_key(key) {
                    proc
                } else {
                    let key = ProcessKey::new();
                    let context = Arc::new(ProcessContext::new(key, None, pid, 0, timestamp));
                    self.processes.insert(key, Arc::clone(&context));
                    *occupied.get_mut() = key;
                    context
                }
            }
            dashmap::mapref::entry::Entry::Vacant(vacant) => {
                let key = ProcessKey::new();
                let context = Arc::new(ProcessContext::new(key, None, pid, 0, timestamp));
                self.processes.insert(key, Arc::clone(&context));
                vacant.insert(key);
                context
            }
        }
    }

    /// Resolves any known process context (active, retained, or tombstone) by its unique `ProcessKey`.
    ///
    /// # Arguments
    ///
    /// * `key` - Synthetic process key.
    ///
    /// # Returns
    ///
    /// `Some(Arc<ProcessContext>)` if tracked in the arena, otherwise `None`.
    #[inline]
    pub fn get_by_key(&self, key: ProcessKey) -> Option<Arc<ProcessContext>> {
        self.processes.get(&key).map(|entry| Arc::clone(entry.value()))
    }

    /// Checks if a process has any currently active (running) child processes.
    ///
    /// # Arguments
    ///
    /// * `parent_key` - Synthetic key of the parent process.
    ///
    /// # Returns
    ///
    /// `true` if at least one direct child process is alive.
    pub fn has_active_children(&self, parent_key: ProcessKey) -> bool {
        if let Some(parent) = self.processes.get(&parent_key) {
            let children = parent.child_keys.read();
            for child_key in children.iter() {
                if let Some(child) = self.processes.get(child_key)
                    && child.is_alive()
                {
                    return true;
                }
            }
        }
        false
    }

    /// Evicts a process permanently from the arena.
    ///
    /// # Arguments
    ///
    /// * `key` - Synthetic process key to evict.
    ///
    /// # Returns
    ///
    /// The evicted `Some(Arc<ProcessContext>)` if it existed, otherwise `None`.
    pub fn evict(&self, key: ProcessKey) -> Option<Arc<ProcessContext>> {
        self.processes.remove(&key).map(|(_, v)| v)
    }

    /// Returns the total number of processes currently tracked in the arena.
    ///
    /// # Returns
    ///
    /// Total process count across active, retained, and tombstone states.
    #[inline]
    pub fn len(&self) -> usize {
        self.processes.len()
    }

    /// Checks whether the arena contains zero processes.
    ///
    /// # Returns
    ///
    /// `true` if the arena is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.processes.is_empty()
    }

    /// Returns the total number of processes currently tracked (active + retained + tombstones).
    ///
    /// # Returns
    ///
    /// Total process count.
    #[inline]
    pub fn total_process_count(&self) -> usize {
        self.processes.len()
    }

    /// Returns the number of currently running active processes.
    ///
    /// # Returns
    ///
    /// Active running process count.
    #[inline]
    pub fn active_process_count(&self) -> usize {
        self.active_pids.len()
    }

    /// Returns a snapshot list of all active operating system PIDs currently tracked.
    pub fn all_active_pids(&self) -> Vec<u32> {
        self.active_pids.iter().map(|entry| *entry.key()).collect()
    }

    /// Returns all process keys currently tracked in the arena.
    ///
    /// # Returns
    ///
    /// A vector of all tracked [`ProcessKey`] identifiers.
    pub fn all_keys(&self) -> Vec<ProcessKey> {
        self.processes.iter().map(|entry| *entry.key()).collect()
    }
}

impl Default for ProcessTree {
    fn default() -> Self {
        Self::new()
    }
}
