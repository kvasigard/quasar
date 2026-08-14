//! Event router and dispatcher distributing pipeline events to registered subscribers.

use crate::pipeline::Event;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::thread::{self, JoinHandle};
use std::time::Duration;

/// The subscriber contract defining interest evaluation and event handling.
pub trait Subscriber: Send + Sync {
    /// Evaluates if this subscriber is interested in this specific event.
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
    /// # Arguments
    ///
    /// * `event` - Shared `Arc` reference to the pipeline `Event`.
    fn on_event(&self, event: &Arc<Event>);
}

/// Central event router distributing ingested telemetry across multiple analytics sinks.
pub struct EventDispatcher {
    rx: Receiver<Event>,
    subscribers: Vec<Box<dyn Subscriber + Send + Sync>>,
}

impl EventDispatcher {
    /// Creates a new `EventDispatcher` consuming from the specified channel receiver.
    ///
    /// # Arguments
    ///
    /// * `rx` - Channel receiver yielding raw pipeline events.
    pub fn new(rx: Receiver<Event>) -> Self {
        Self {
            rx,
            subscribers: Vec::new(),
        }
    }

    /// Registers a new subscriber sink to receive dispatched events.
    ///
    /// # Arguments
    ///
    /// * `sub` - Boxed subscriber implementation.
    pub fn add_subscriber(&mut self, sub: Box<dyn Subscriber + Send + Sync>) {
        self.subscribers.push(sub);
    }

    /// Launches the dispatch routing loop in a background worker thread.
    ///
    /// # Arguments
    ///
    /// * `shutdown_flag` - Atomic flag checked periodically to initiate graceful termination.
    ///
    /// # Returns
    ///
    /// A `JoinHandle` for the spawned background thread.
    pub fn start(self, shutdown_flag: Arc<AtomicBool>) -> JoinHandle<()> {
        thread::spawn(move || {
            log::debug!(target: "dispatcher", "EventDispatcher background thread started.");

            // Loop until the shutdown flag is set to true
            while !shutdown_flag.load(Ordering::SeqCst) {
                match self.rx.recv_timeout(Duration::from_millis(100)) {
                    Ok(event) => {
                        let event_ptr = Arc::new(event);

                        for sub in &self.subscribers {
                            if sub.is_interested(&event_ptr) {
                                sub.on_event(&event_ptr);
                            }
                        }
                    }
                    Err(RecvTimeoutError::Timeout) => {
                        continue;
                    }
                    Err(RecvTimeoutError::Disconnected) => {
                        break;
                    }
                }
            }

            log::debug!(target: "dispatcher", "Event bus stopped by signal or disconnection. Dispatcher terminating.");
        })
    }
}
