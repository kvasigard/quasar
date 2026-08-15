//! Centralized system-wide context facade and cross-domain correlation engine.

use std::sync::Arc;

use crate::context::process::{ProcessContext, ProcessKey};
use crate::context::process_tree::ProcessTree;

/// Centralized execution context container holding all system-wide entity domains.
pub struct SystemContext {
    /// Process topology, execution lifecycles, and ancestry index.
    processes: ProcessTree,
    // pub files: FileRegistry,
    // pub registry: RegistryTree,
    // pub network: NetworkTracker,
    // pub memory: MemoryRegionTracker,
}

impl Default for SystemContext {
    fn default() -> Self {
        Self::new()
    }
}

impl SystemContext {
    /// Creates a new `SystemContext` with initialized subsystems.
    pub fn new() -> Self {
        Self {
            processes: ProcessTree::new(),
        }
    }

    /// Inserts a new process context into the process tree.
    ///
    /// # Arguments
    ///
    /// * `context` - The initialized `ProcessContext` for the new process.
    ///
    /// # Returns
    ///
    /// An `Arc<ProcessContext>` pointing to the inserted record.
    pub fn insert_process(&self, context: ProcessContext) -> Arc<ProcessContext> {
        self.processes.insert_process(context)
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
        self.processes.exit_process(pid, exit_status, timestamp)
    }

    /// Resolves the active process context for an OS PID.
    ///
    /// # Arguments
    ///
    /// * `pid` - The target Process ID.
    ///
    /// # Returns
    ///
    /// `Some(Arc<ProcessContext>)` if the PID is actively mapped, otherwise `None`.
    #[inline]
    pub fn get_process(&self, pid: u32) -> Option<Arc<ProcessContext>> {
        self.processes.get_by_pid(pid)
    }

    /// Resolves a process context by its globally unique synthetic `ProcessKey`.
    ///
    /// # Arguments
    ///
    /// * `key` - The synthetic `ProcessKey`.
    ///
    /// # Returns
    ///
    /// `Some(Arc<ProcessContext>)` if the key exists in the process arena, otherwise `None`.
    #[inline]
    pub fn get_process_by_key(&self, key: ProcessKey) -> Option<Arc<ProcessContext>> {
        self.processes.get_by_key(key)
    }

    /// Traverses the ancestry tree backwards starting from `key` up to the root parent.
    ///
    /// # Arguments
    ///
    /// * `key` - The synthetic `ProcessKey` of the starting node.
    ///
    /// # Returns
    ///
    /// A vector of ancestor contexts starting from `[Self, Parent, Grandparent, ...]`.
    #[inline]
    pub fn get_lineage(&self, key: ProcessKey) -> Vec<Arc<ProcessContext>> {
        self.processes.get_lineage(key)
    }

    /// Purges historical processes whose exit timestamps are older than the threshold.
    ///
    /// # Arguments
    ///
    /// * `cutoff_timestamp` - Exited processes with timestamp earlier than this cutoff are removed.
    ///
    /// # Returns
    ///
    /// Number of pruned process contexts.
    pub fn prune_retained(&self, cutoff_timestamp: i64) -> usize {
        self.processes.prune_retained(cutoff_timestamp)
    }
}
