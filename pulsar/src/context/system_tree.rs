//! In-memory process graph, two-tier lookup engine, and retention manager.

use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, RwLock},
};

use crate::context::process::{ProcessContext, ProcessKey};

/// Concurrent graph and relational storage container for process trees.
///
/// **Why a Two-Tier Architecture?**
/// 1. `active_pids`: Fast O(1) table mapping raw OS PIDs to synthetic `ProcessKey`s.
///    Only holds running processes so recycled PIDs never collide.
/// 2. `processes`: The historical context arena. Holds active AND recently dead
///    processes for forensic lineage lookups.
/// 3. `retention_queue`: Time-ordered FIFO queue to prune old exited processes
///    and prevent memory leaks.
pub struct SystemTree {
    /// Ingress index: Active PID -> Current ProcessKey.
    active_pids: RwLock<HashMap<u32, ProcessKey>>,
    /// Relational Arena: `ProcessKey` -> `Arc<ProcessContext>`.
    processes: RwLock<HashMap<ProcessKey, Arc<ProcessContext>>>,
    /// Retention Tracker: (ProcessKey, ExitTimestamp) ordered by termination time.
    retention_queue: RwLock<VecDeque<(ProcessKey, i64)>>,
}

impl SystemTree {
    /// Creates a new empty `SystemTree`.
    ///
    /// # Returns
    ///
    /// An empty `SystemTree` with initialized indices.
    pub fn new() -> Self {
        Self {
            active_pids: RwLock::new(HashMap::new()),
            processes: RwLock::new(HashMap::new()),
            retention_queue: RwLock::new(VecDeque::new()),
        }
    }

    /// Inserts a new process, links parent-child relationships, and activates the PID.
    ///
    /// # Arguments
    ///
    /// * `context` - The initialized `ProcessContext` for the new process.
    ///
    /// # Returns
    ///
    /// An `Arc<ProcessContext>` pointing to the inserted record.
    pub fn insert_process(&self, mut context: ProcessContext) -> Arc<ProcessContext> {
        let pid = context.pid;
        let parent_pid = context.parent_pid;
        let key = context.key;

        // Step 1: Look up parent's synthetic key via the active PID index
        let resolved_parent_key = {
            let active = self.active_pids.read().unwrap();
            active.get(&parent_pid).copied()
        };

        context.parent_key = resolved_parent_key;
        let context_arc = Arc::new(context);

        // Step 2: Register in historical arena and link under parent's child list
        {
            let mut arena = self.processes.write().unwrap();
            arena.insert(key, Arc::clone(&context_arc));

            if let Some(parent_ctx) = resolved_parent_key.and_then(|parent_k| arena.get(&parent_k)) {
                parent_ctx.child_keys.write().unwrap().insert(key);
            }
        }

        // Step 3: Activate PID routing for incoming telemetry
        {
            let mut active = self.active_pids.write().unwrap();
            active.insert(pid, key);
        }

        log::trace!(
            target: "system_tree",
            "Inserted process: PID {pid}, Key {key:?}, Parent PID {parent_pid}, Parent Key {resolved_parent_key:?}"
        );

        context_arc
    }

    /// Marks a process as terminated, unlinks its PID immediately, and queues retention.
    ///
    /// # Arguments
    ///
    /// * `pid` - The Process ID of the exiting process.
    /// * `exit_status` - The exit code of the process.
    /// * `timestamp` - The termination timestamp.
    ///
    /// # Returns
    ///
    /// `Some(Arc<ProcessContext>)` if the PID was found in the active index, otherwise `None`.
    pub fn exit_process(
        &self,
        pid: u32,
        exit_status: u32,
        timestamp: i64,
    ) -> Option<Arc<ProcessContext>> {
        // Step 1: Remove from active PID routing so recycled PIDs do not hit an exited instance
        let key = {
            let mut active = self.active_pids.write().unwrap();
            active.remove(&pid)?
        };

        // Step 2: Mark termination in historical arena and enqueue for deferred cleanup
        let arena = self.processes.read().unwrap();
        if let Some(context) = arena.get(&key) {
            context.mark_terminated(exit_status, timestamp);

            let mut queue = self.retention_queue.write().unwrap();
            queue.push_back((key, timestamp));

            log::debug!(
                target: "system_tree",
                "Process exited: PID {pid}, Key {key:?}, ExitStatus {exit_status:#x}"
            );

            return Some(Arc::clone(context));
        }

        None
    }

    /// Resolves an active process context using its current OS PID.
    ///
    /// # Arguments
    ///
    /// * `pid` - The Process ID to query.
    ///
    /// # Returns
    ///
    /// `Some(Arc<ProcessContext>)` if the PID is currently running, otherwise `None`.
    #[inline]
    pub fn get_by_pid(&self, pid: u32) -> Option<Arc<ProcessContext>> {
        let active = self.active_pids.read().unwrap();
        let key = active.get(&pid)?;
        self.get_by_key(*key)
    }

    /// Resolves any known process context (active or retained) by its unique `ProcessKey`.
    ///
    /// # Arguments
    ///
    /// * `key` - The synthetic `ProcessKey`.
    ///
    /// # Returns
    ///
    /// `Some(Arc<ProcessContext>)` if the key exists in the historical arena, otherwise `None`.
    #[inline]
    pub fn get_by_key(&self, key: ProcessKey) -> Option<Arc<ProcessContext>> {
        let arena = self.processes.read().unwrap();
        arena.get(&key).cloned()
    }

    /// Traverses the process ancestry upwards to the root ancestor.
    ///
    /// # Arguments
    ///
    /// * `key` - The synthetic key of the starting process.
    ///
    /// # Returns
    ///
    /// A vector of ancestor contexts starting from `[Self, Parent, Grandparent, ...]`.
    pub fn get_lineage(&self, key: ProcessKey) -> Vec<Arc<ProcessContext>> {
        let mut lineage = Vec::new();
        let arena = self.processes.read().unwrap();
        let mut current_key = Some(key);

        while let Some(k) = current_key {
            if let Some(ctx) = arena.get(&k) {
                lineage.push(Arc::clone(ctx));
                current_key = ctx.parent_key;
            } else {
                break;
            }
        }

        lineage
    }

    /// Prunes expired processes from the arena whose exit time is older than `cutoff_timestamp`.
    ///
    /// # Arguments
    ///
    /// * `cutoff_timestamp` - Exited processes with timestamp earlier than this cutoff are removed.
    ///
    /// # Returns
    ///
    /// The number of pruned process records.
    pub fn prune_retained(&self, cutoff_timestamp: i64) -> usize {
        let mut keys_to_remove = Vec::new();

        {
            let mut queue = self.retention_queue.write().unwrap();
            while let Some(&(key, exit_time)) = queue.front() {
                if exit_time < cutoff_timestamp {
                    keys_to_remove.push(key);
                    queue.pop_front();
                } else {
                    // Retention queue is FIFO ordered by exit timestamp
                    break;
                }
            }
        }

        let pruned_count = keys_to_remove.len();
        if !keys_to_remove.is_empty() {
            let mut arena = self.processes.write().unwrap();
            for key in keys_to_remove {
                arena.remove(&key);
            }
            log::info!(
                target: "system_tree",
                "Pruned {pruned_count} expired records from context arena"
            );
        }

        pruned_count
    }
}

impl Default for SystemTree {
    fn default() -> Self {
        Self::new()
    }
}
