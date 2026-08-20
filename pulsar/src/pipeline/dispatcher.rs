//! Multi-threaded event router and dispatcher worker pool distributing pipeline events.

use std::sync::Arc;
use std::thread::{self, JoinHandle};
use crossbeam_channel::Receiver;

use crate::pipeline::event::Event;
use crate::pipeline::ingress::IngressParser;
use crate::sensors::etw::EventRecord;

/// The subscriber contract defining interest evaluation and event handling for detection sinks.
pub trait Subscriber: Send + Sync {
    /// Evaluates if this subscriber is interested in this specific domain event.
    ///
    /// # Arguments
    ///
    /// * `event` - Reference to the incoming pipeline `Event`.
    ///
    /// # Returns
    ///
    /// `true` if this subscriber should receive the event for processing.
    fn is_interested(&self, event: &Event) -> bool;

    /// Processes an accepted event.
    ///
    /// When this function executes, `SystemContext` is guaranteed to be 100% updated with this event.
    ///
    /// # Arguments
    ///
    /// * `event` - Shared `Arc` reference to the strongly-typed `Event`.
    fn on_event(&self, event: &Arc<Event>);
}

/// Handle managing the pool of background dispatcher worker threads.
pub struct DispatcherHandle {
    workers: Vec<JoinHandle<()>>,
}

impl DispatcherHandle {
    /// Waits for all worker threads in the dispatcher pool to finish.
    ///
    /// # Returns
    ///
    /// `Ok(())` upon successful thread termination.
    ///
    /// # Errors
    ///
    /// Returns `Err` if any worker thread panicked.
    pub fn join(self) -> std::thread::Result<()> {
        for handle in self.workers {
            handle.join()?;
        }
        Ok(())
    }
}

/// Central multi-threaded event router distributing ingested telemetry across analytical detection sinks.
pub struct EventDispatcher {
    rx: Receiver<EventRecord>,
    subscribers: Vec<Box<dyn Subscriber + Send + Sync>>,
    ingress_parser: Arc<IngressParser>,
    num_workers: usize,
}

impl EventDispatcher {
    /// Creates a new `EventDispatcher` consuming from the specified crossbeam channel receiver.
    ///
    /// # Arguments
    ///
    /// * `rx` - Crossbeam channel receiver yielding raw ETW records.
    ///
    /// # Returns
    ///
    /// An initialized [`EventDispatcher`] builder.
    pub fn new(rx: Receiver<EventRecord>) -> Self {
        let num_workers = thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(2)
            .clamp(1, 4);

        Self {
            rx,
            subscribers: Vec::new(),
            ingress_parser: Arc::new(IngressParser::new()),
            num_workers,
        }
    }

    /// Configures the number of concurrent worker threads in the dispatcher pool.
    ///
    /// # Arguments
    ///
    /// * `workers` - Number of concurrent worker threads.
    ///
    /// # Returns
    ///
    /// The updated [`EventDispatcher`] builder.
    pub fn with_workers(mut self, workers: usize) -> Self {
        self.num_workers = workers.max(1);
        self
    }

    /// Registers a new detection subscriber to receive dispatched events.
    ///
    /// # Arguments
    ///
    /// * `sub` - The boxed subscriber sink to add.
    pub fn add_subscriber(&mut self, sub: Box<dyn Subscriber + Send + Sync>) {
        self.subscribers.push(sub);
    }

    /// Launches the concurrent worker pool in background threads.
    ///
    /// # Returns
    ///
    /// A [`DispatcherHandle`] managing all worker thread join handles.
    pub fn start(self) -> DispatcherHandle {
        let subscribers = Arc::new(self.subscribers);
        let ingress = Arc::clone(&self.ingress_parser);
        let mut workers = Vec::with_capacity(self.num_workers);

        log::info!(
            target: "dispatcher",
            "Starting EventDispatcher pool with {} concurrent worker threads",
            self.num_workers
        );

        for worker_id in 0..self.num_workers {
            let rx = self.rx.clone();
            let subs = Arc::clone(&subscribers);
            let ingress_parser = Arc::clone(&ingress);

            let handle = thread::Builder::new()
                .name(format!("pulsar-dispatcher-{}", worker_id))
                .spawn(move || {
                    log::debug!(
                        target: "dispatcher",
                        "Dispatcher worker thread [{}] active",
                        worker_id
                    );

                    while let Ok(raw_record) = rx.recv() {
                        // Stage 1: Ingress Pre-Processing, Context Ingestion, and Stack Correlation
                        if let Some(domain_event) = ingress_parser.process_raw_record(raw_record) {
                            // Stage 2: Concurrent Detection Dispatch to Analytical Sinks
                            let event_ptr = Arc::new(domain_event);

                            let _span = tracing::trace_span!("dispatch_event").entered();
                            for sub in subs.iter() {
                                if sub.is_interested(&event_ptr) {
                                    sub.on_event(&event_ptr);
                                }
                            }
                        }
                    }

                    log::debug!(
                        target: "dispatcher",
                        "Dispatcher worker thread [{}] terminating",
                        worker_id
                    );
                })
                .expect("Failed to spawn dispatcher worker thread");

            workers.push(handle);
        }

        DispatcherHandle { workers }
    }
}
