//! Background Garbage Collection worker and retention manager.

use std::{
    collections::VecDeque,
    sync::Arc,
    thread::{self, JoinHandle},
    time::Duration,
};
use crossbeam_channel::{bounded, select, Receiver, Sender};
use parking_lot::RwLock;

use crate::context::config::ContextConfig;
use crate::context::identity::ProcessKey;
use crate::context::registries::ProcessTree;

/// Manages eviction queues and orchestrates dual-trigger garbage collection sweeps.
pub struct RetentionManager {
    /// Time-ordered FIFO queue of exited processes: `(ProcessKey, ExitTimestamp)`.
    exit_queue: RwLock<VecDeque<(ProcessKey, i64)>>,
    /// Active configuration parameters.
    config: ContextConfig,
    /// Shutdown channel sender for the background GC worker thread.
    shutdown_tx: Sender<()>,
    /// Shutdown channel receiver.
    shutdown_rx: Receiver<()>,
}

impl RetentionManager {
    /// Creates a new `RetentionManager`.
    ///
    /// # Arguments
    ///
    /// * `config` - Retention parameters governing TTL and capacity thresholds.
    ///
    /// # Returns
    ///
    /// An initialized [`RetentionManager`].
    pub fn new(config: ContextConfig) -> Self {
        let (shutdown_tx, shutdown_rx) = bounded(1);
        Self {
            exit_queue: RwLock::new(VecDeque::new()),
            config,
            shutdown_tx,
            shutdown_rx,
        }
    }

    /// Enqueues an exited process into the retention tracking queue.
    ///
    /// # Arguments
    ///
    /// * `key` - Synthetic process key of the terminated process.
    /// * `timestamp` - Termination timestamp.
    pub fn enqueue_exit(&self, key: ProcessKey, timestamp: i64) {
        self.exit_queue.write().push_back((key, timestamp));
    }

    /// Performs a single GC pass evaluating both TTL and capacity constraints.
    ///
    /// # Arguments
    ///
    /// * `processes` - Reference to the process arena.
    /// * `current_time` - Current system timestamp for TTL evaluation.
    ///
    /// # Returns
    ///
    /// A tuple `(evicted_count, tombstones_created)`.
    #[tracing::instrument(name = "retention_gc_pass", skip(self, processes), level = "debug")]
    pub fn run_gc_pass(&self, processes: &ProcessTree, current_time: i64) -> (usize, usize) {
        let mut tombstones_created = 0;
        let mut evicted_count = 0;

        let cutoff_time = current_time - self.config.retention_ttl_ms;
        let is_over_capacity = processes.total_process_count() > self.config.max_process_capacity;

        let mut queue = self.exit_queue.write();
        let mut retained_in_queue = VecDeque::new();

        while let Some((key, exit_time)) = queue.pop_front() {
            let is_expired = exit_time < cutoff_time;

            if !is_expired && !is_over_capacity {
                // Not expired and within capacity -> keep in queue
                retained_in_queue.push_back((key, exit_time));
                continue;
            }

            // Check if process exists
            let Some(proc) = processes.get_by_key(key) else {
                continue;
            };

            // Rule 1: Suspicion Pinning (Never evict flagged / pinned entities)
            if proc.is_pinned() {
                retained_in_queue.push_back((key, exit_time));
                continue;
            }

            // Rule 2: Ancestry Preservation via Tombstones
            if self.config.enable_tombstones && processes.has_active_children(key) {
                if !proc.is_tombstone() {
                    proc.convert_to_tombstone();
                    tombstones_created += 1;
                    log::trace!(
                        target: "system_gc",
                        "Converted expired process {key} to tombstone (has active descendants)"
                    );
                }
                // Keep tombstone in queue to be re-evaluated when children exit
                retained_in_queue.push_back((key, exit_time));
            } else {
                // Rule 3: Permanent Eviction
                processes.evict(key);
                evicted_count += 1;
                log::trace!(
                    target: "system_gc",
                    "Evicted process {key} from memory"
                );
            }
        }

        *queue = retained_in_queue;

        if tombstones_created > 0 || evicted_count > 0 {
            log::debug!(
                target: "system_gc",
                "GC Sweep completed: {evicted_count} evicted, {tombstones_created} converted to tombstones (Total active: {}, Total tracked: {})",
                processes.active_process_count(),
                processes.total_process_count()
            );
        }

        (evicted_count, tombstones_created)
    }

    /// Spawns a background GC thread that runs periodically according to config.
    ///
    /// Consumes 0.0% CPU when waiting between GC intervals via `crossbeam_channel::select!`.
    ///
    /// # Arguments
    ///
    /// * `processes` - Shared pointer to the process tree arena.
    ///
    /// # Returns
    ///
    /// A [`JoinHandle`] for the spawned worker thread.
    pub fn spawn_gc_thread(
        self: Arc<Self>,
        processes: Arc<ProcessTree>,
    ) -> JoinHandle<()> {
        let shutdown_rx = self.shutdown_rx.clone();
        let interval = Duration::from_millis(self.config.gc_interval_ms);

        thread::Builder::new()
            .name("pulsar-context-gc".to_string())
            .spawn(move || {
                log::info!(target: "system_gc", "Background Context GC worker thread started");

                loop {
                    select! {
                        recv(shutdown_rx) -> _ => {
                            break;
                        }
                        recv(crossbeam_channel::after(interval)) -> _ => {
                            let now = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .map(|d| d.as_millis() as i64)
                                .unwrap_or(0);

                            self.run_gc_pass(&processes, now);
                        }
                    }
                }

                log::info!(target: "system_gc", "Background Context GC worker thread exiting");
            })
            .expect("Failed to spawn background Context GC thread")
    }

    /// Signals the background GC thread to stop immediately.
    pub fn stop(&self) {
        let _ = self.shutdown_tx.try_send(());
    }
}
