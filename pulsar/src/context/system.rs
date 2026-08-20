//! Centralized system-wide context facade, domain registries, and query coordinator.

use std::sync::Arc;

use crate::context::config::ContextConfig;
use crate::context::correlation::InjectionCorrelator;
use crate::context::identity::{FileKey, ProcessKey};
use crate::context::models::file::FileContext;
use crate::context::models::interaction::InteractionRecord;
use crate::context::models::process::ProcessContext;
use crate::context::query::{InteractionQuery, ProcessRef};
use crate::context::registries::{
    FileRegistry, InteractionRegistry, NetworkRegistry, ProcessTree,
};
use crate::context::retention::RetentionManager;

/// Centralized, concurrent execution context container holding all system-wide entity domains.
pub struct SystemContext {
    /// Process topology, execution lifecycles, and ancestry tree.
    pub(crate) processes: Arc<ProcessTree>,
    /// Filesystem file tracking, path normalization, and access history.
    pub(crate) files: Arc<FileRegistry>,
    /// Active network sockets and process connection mapping.
    pub(crate) network: Arc<NetworkRegistry>,
    /// Cross-entity interaction ledger and activity ring buffer.
    pub(crate) interactions: Arc<InteractionRegistry>,
    /// Multi-step cross-process injection correlator state machine.
    pub(crate) injection_correlator: InjectionCorrelator,
    /// Dual-trigger garbage collection and retention manager.
    pub(crate) retention: Arc<RetentionManager>,
}

impl Default for SystemContext {
    fn default() -> Self {
        Self::new_with_config(ContextConfig::default())
    }
}

impl SystemContext {
    /// Creates a new `SystemContext` with default configuration and spawns the background GC worker.
    ///
    /// # Returns
    ///
    /// An initialized [`SystemContext`] singleton instance.
    pub fn new() -> Self {
        Self::new_with_config(ContextConfig::default())
    }

    /// Creates a new `SystemContext` with explicit configuration options.
    ///
    /// # Arguments
    ///
    /// * `config` - Custom retention and capacity parameters.
    ///
    /// # Returns
    ///
    /// An initialized [`SystemContext`] instance with active background GC.
    pub fn new_with_config(config: ContextConfig) -> Self {
        let max_interactions = config.max_interaction_capacity;
        let processes = Arc::new(ProcessTree::new());
        let files = Arc::new(FileRegistry::new());
        let network = Arc::new(NetworkRegistry::new());
        let interactions = Arc::new(InteractionRegistry::new(max_interactions));
        let injection_correlator = InjectionCorrelator::new();
        let retention = Arc::new(RetentionManager::new(config));

        // Spawn background GC worker thread
        let retention_clone = Arc::clone(&retention);
        let processes_clone = Arc::clone(&processes);
        retention_clone.spawn_gc_thread(processes_clone);

        log::info!(
            target: "system_context",
            "SystemContext initialized successfully with background GC"
        );

        Self {
            processes,
            files,
            network,
            interactions,
            injection_correlator,
            retention,
        }
    }

    /// Creates an isolated `SystemContext` for unit tests (no background thread).
    ///
    /// # Arguments
    ///
    /// * `config` - Test configuration parameters.
    ///
    /// # Returns
    ///
    /// An isolated [`SystemContext`] without background worker threads.
    pub fn new_for_test(config: ContextConfig) -> Self {
        let max_interactions = config.max_interaction_capacity;
        let processes = Arc::new(ProcessTree::new());
        let files = Arc::new(FileRegistry::new());
        let network = Arc::new(NetworkRegistry::new());
        let interactions = Arc::new(InteractionRegistry::new(max_interactions));
        let injection_correlator = InjectionCorrelator::new();
        let retention = Arc::new(RetentionManager::new(config));

        Self {
            processes,
            files,
            network,
            interactions,
            injection_correlator,
            retention,
        }
    }

    // --- Process Domain Operations ---

    /// Inserts a new process into the tree and links ancestry.
    ///
    /// # Arguments
    ///
    /// * `context` - The process context to insert.
    ///
    /// # Returns
    ///
    /// An [`Arc<ProcessContext>`] reference stored in the arena.
    pub fn insert_process(&self, context: ProcessContext) -> Arc<ProcessContext> {
        self.processes.insert_process(context)
    }

    /// Marks a process as terminated, unmaps PID, and enqueues for retention GC.
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
        let exited = self.processes.exit_process(pid, exit_status, timestamp)?;
        self.retention.enqueue_exit(exited.key, timestamp);
        Some(exited)
    }

    /// Resolves an active process context by OS PID.
    ///
    /// # Arguments
    ///
    /// * `pid` - Operating system Process ID.
    ///
    /// # Returns
    ///
    /// `Some(Arc<ProcessContext>)` if currently running, otherwise `None`.
    #[inline]
    pub fn get_process(&self, pid: u32) -> Option<Arc<ProcessContext>> {
        self.processes.get_by_pid(pid)
    }

    /// Resolves any tracked process context (active, retained, or tombstone) by `ProcessKey`.
    ///
    /// # Arguments
    ///
    /// * `key` - Synthetic process key.
    ///
    /// # Returns
    ///
    /// `Some(Arc<ProcessContext>)` if tracked in the arena, otherwise `None`.
    #[inline]
    pub fn get_process_by_key(&self, key: ProcessKey) -> Option<Arc<ProcessContext>> {
        self.processes.get_by_key(key)
    }

    // --- Fluent Query DSL Entry Points ---

    /// Returns a fluent query handle for an active process by OS PID.
    ///
    /// # Arguments
    ///
    /// * `pid` - Operating system Process ID.
    ///
    /// # Returns
    ///
    /// `Some(ProcessRef)` query wrapper if currently active, otherwise `None`.
    ///
    /// # Example
    /// ```ignore
    /// if let Some(proc) = ctx.process(1234) {
    ///     let is_lolbin = proc.ancestors().any(|p| p.image_name() == "winword.exe");
    /// }
    /// ```
    #[inline]
    pub fn process(&self, pid: u32) -> Option<ProcessRef<'_>> {
        let inner = self.processes.get_by_pid(pid)?;
        Some(ProcessRef::new(self, inner))
    }

    /// Returns a fluent query handle for any tracked process by its `ProcessKey`.
    ///
    /// # Arguments
    ///
    /// * `key` - Synthetic process key.
    ///
    /// # Returns
    ///
    /// `Some(ProcessRef)` query wrapper if tracked, otherwise `None`.
    #[inline]
    pub fn process_by_key(&self, key: ProcessKey) -> Option<ProcessRef<'_>> {
        let inner = self.processes.get_by_key(key)?;
        Some(ProcessRef::new(self, inner))
    }

    /// Returns a fluent query builder for querying and filtering interaction records.
    ///
    /// # Returns
    ///
    /// An [`InteractionQuery`] builder.
    #[inline]
    pub fn query_interactions(&self) -> InteractionQuery<'_> {
        InteractionQuery::new(self)
    }

    // --- File Domain Operations ---

    /// Resolves or registers a normalized filesystem path.
    ///
    /// # Arguments
    ///
    /// * `path` - The raw path string.
    /// * `timestamp` - Current timestamp.
    ///
    /// # Returns
    ///
    /// An [`Arc<FileContext>`] reference.
    pub fn get_or_create_file(&self, path: &str, timestamp: i64) -> Arc<FileContext> {
        self.files.get_or_create(path, timestamp)
    }

    /// Looks up a tracked file by path if already observed.
    ///
    /// # Arguments
    ///
    /// * `path` - File path to query.
    ///
    /// # Returns
    ///
    /// `Some(Arc<FileContext>)` if tracked, otherwise `None`.
    #[inline]
    pub fn file(&self, path: &str) -> Option<Arc<FileContext>> {
        self.files.get_by_path(path)
    }

    /// Alias for `file`.
    ///
    /// # Arguments
    ///
    /// * `path` - File path to query.
    ///
    /// # Returns
    ///
    /// `Some(Arc<FileContext>)` if tracked, otherwise `None`.
    #[inline]
    pub fn get_file(&self, path: &str) -> Option<Arc<FileContext>> {
        self.file(path)
    }

    /// Looks up a tracked file by synthetic FileKey.
    ///
    /// # Arguments
    ///
    /// * `key` - Synthetic file key.
    ///
    /// # Returns
    ///
    /// `Some(Arc<FileContext>)` if tracked, otherwise `None`.
    #[inline]
    pub fn file_by_key(&self, key: FileKey) -> Option<Arc<FileContext>> {
        self.files.get_by_key(key)
    }

    /// Alias for `file_by_key`.
    ///
    /// # Arguments
    ///
    /// * `key` - Synthetic file key.
    ///
    /// # Returns
    ///
    /// `Some(Arc<FileContext>)` if tracked, otherwise `None`.
    #[inline]
    pub fn get_file_by_key(&self, key: FileKey) -> Option<Arc<FileContext>> {
        self.file_by_key(key)
    }

    // --- Interaction Domain Operations ---

    /// Commits an interaction event into the centralized activity ledger.
    ///
    /// # Arguments
    ///
    /// * `record` - The interaction record to persist.
    ///
    /// # Returns
    ///
    /// An [`Arc<InteractionRecord>`] reference.
    pub fn record_interaction(&self, record: InteractionRecord) -> Arc<InteractionRecord> {
        self.interactions.record(record)
    }

    // --- Correlation Operations ---

    /// Returns a reference to the multi-step code injection correlator state machine.
    #[inline]
    pub fn injection_correlator(&self) -> &InjectionCorrelator {
        &self.injection_correlator
    }

    // --- Maintenance & GC ---

    /// Manually triggers a GC pass across the process tree (useful in tests).
    ///
    /// # Arguments
    ///
    /// * `now` - Current timestamp.
    ///
    /// # Returns
    ///
    /// A tuple `(evicted_count, tombstones_created)`.
    pub fn run_gc_pass(&self, now: i64) -> (usize, usize) {
        self.retention.run_gc_pass(&self.processes, now)
    }
}
