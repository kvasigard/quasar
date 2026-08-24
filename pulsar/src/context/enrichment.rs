//! Asynchronous context metadata enrichment subsystem.
//!
//! Offloads heavy, blocking operating system inspection tasks (such as Authenticode signature
//! verification, PE header export table extraction, and virtual memory layout VAD queries)
//! to a dedicated background worker thread.
//!
//! This ensures that Stage 1 Ingress and Stage 2 Event Dispatching remain sub-microsecond
//! and never drop real-time kernel telemetry under high system load.

use crate::context::identity::{FileKey, ProcessKey};
use crossbeam_channel::{Receiver, Sender, TrySendError};

/// Asynchronous metadata enrichment jobs processed off the real-time hot path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnrichmentTask {
    /// Enriches a newly discovered file on disk (PE exports, Authenticode signature, SHA-256).
    NewFile(FileKey),
    /// Asynchronously scans the virtual memory layout (VAD) of a target process.
    ScanMemoryVad(ProcessKey),
}

/// Thread-safe, non-blocking queue manager for dispatching enrichment jobs to the background worker.
pub struct EnrichmentQueue {
    /// Bounded lock-free channel sender.
    sender: Sender<EnrichmentTask>,
}

impl EnrichmentQueue {
    /// Instantiates a new [`EnrichmentQueue`] with a fixed ring-buffer capacity.
    ///
    /// # Arguments
    ///
    /// * `capacity` - Maximum number of pending enrichment tasks before backpressure drops events.
    ///
    /// # Returns
    ///
    /// A tuple containing the initialized [`EnrichmentQueue`] and the corresponding [`Receiver`].
    pub fn new(capacity: usize) -> (Self, Receiver<EnrichmentTask>) {
        let (sender, receiver) = crossbeam_channel::bounded(capacity);
        (Self { sender }, receiver)
    }

    /// Enqueues an enrichment task using non-blocking semantics.
    ///
    /// If the queue is saturated, the task is dropped with a debug log message rather than
    /// stalling the calling ingestion thread.
    ///
    /// # Arguments
    ///
    /// * `task` - The [`EnrichmentTask`] to dispatch.
    ///
    /// # Returns
    ///
    /// `true` if the task was successfully enqueued, `false` if the queue is full or disconnected.
    pub fn queue_task(&self, task: EnrichmentTask) -> bool {
        match self.sender.try_send(task) {
            Ok(_) => true,
            Err(TrySendError::Full(_)) => {
                log::debug!(
                    target: "context_enrichment",
                    "Enrichment queue is full; dropping task to preserve ingestion throughput"
                );
                false
            }
            Err(TrySendError::Disconnected(_)) => {
                log::trace!(
                    target: "context_enrichment",
                    "Enrichment worker is disconnected; dropping task"
                );
                false
            }
        }
    }

    /// Spawns the dedicated background enrichment worker thread named `"pulsar-context-enrichment"`.
    ///
    /// # Arguments
    ///
    /// * `receiver` - Channel receiver listening for dispatched enrichment jobs.
    ///
    /// # Returns
    ///
    /// A [`std::thread::JoinHandle`].
    pub fn spawn_worker(
        self: std::sync::Arc<Self>,
        receiver: Receiver<EnrichmentTask>,
    ) -> std::thread::JoinHandle<()> {
        std::thread::Builder::new()
            .name("pulsar-enrich".into())
            .spawn(move || {
                log::info!(
                    target: "context_enrichment",
                    "Background context enrichment worker started"
                );

                while let Ok(task) = receiver.recv() {
                    match task {
                        EnrichmentTask::NewFile(file_key) => {
                            log::trace!(
                                target: "context_enrichment",
                                "Processing NewFile enrichment for FileKey {:?}",
                                file_key
                            );

                            use crate::context::CONTEXT;
                            use crate::context::models::file::{DigitalSignature, FileFormatInfo};
                            use crate::helpers::pe::{PeError, PeParser};

                            if let Some(file_ctx) = CONTEXT.files.get_by_key(file_key) {
                                let path = file_ctx.path.clone();
                                if !path.is_empty() && std::path::Path::new(&path).exists() {
                                    match PeParser::parse_file(&path) {
                                        Ok(pe_info) => {
                                            log::debug!(
                                                target: "context_enrichment",
                                                "Enriched PE file {} (64-bit: {}, exports: {})",
                                                path,
                                                pe_info.is_64bit,
                                                pe_info.exports.as_ref().map(|e| e.exports.len()).unwrap_or(0)
                                            );
                                            file_ctx.set_format_info(FileFormatInfo::Pe(std::sync::Arc::new(pe_info)));
                                        }
                                        Err(PeError::InvalidDosSignature) => {
                                            log::trace!(
                                                target: "context_enrichment",
                                                "File {} is not a PE image",
                                                path
                                            );
                                        }
                                        Err(err) => {
                                            log::debug!(
                                                target: "context_enrichment",
                                                "Failed to parse PE headers for {}: {}",
                                                path,
                                                err
                                            );
                                        }
                                    }

                                    // Perform Digital Signature Verification off the hot path
                                    let signature = DigitalSignature::verify_file(&path);
                                    log::debug!(
                                        target: "context_enrichment",
                                        "Verified signature for {}: status={:?}, is_ms={}, signer={:?}",
                                        path,
                                        signature.status,
                                        signature.is_microsoft,
                                        signature.signer_name
                                    );
                                    file_ctx.set_signature(signature);
                                }
                            }
                        }
                        EnrichmentTask::ScanMemoryVad(process_key) => {
                            log::trace!(
                                target: "context_enrichment",
                                "Processing ScanMemoryVad for ProcessKey {:?}",
                                process_key
                            );
                            // Placeholder for VirtualQueryEx VAD scan
                        }
                    }
                }

                log::info!(
                    target: "context_enrichment",
                    "Background context enrichment worker stopped"
                );
            })
            .expect("Failed to spawn background context enrichment worker")
    }
}
