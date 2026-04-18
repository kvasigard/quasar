use crate::pipeline::Event;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::thread::{self, JoinHandle};
use std::time::Duration;

/// The subscriber contract.
/// Receives a reference to the Arc to avoid unnecessarily incrementing
/// the reference counter if the subscriber decides to ignore the event.
pub trait Subscriber: Send + Sync {
    /// Evaluates if this subscriber is interested in this specific event.
    /// Used by the Dispatcher to route events properly (e.g., matching GUID/Opcode).
    /// This must be a fast, synchronous check.
    fn is_interested(&self, event: &Event) -> bool;

    /// Processes the event.
    /// Contextual filters and heavy logic happen here.
    fn on_event(&self, event: &Arc<Event>);
}

pub struct EventDispatcher {
    // Channel receiver for raw events
    rx: Receiver<Event>,
    // Flat list of subscribed sinks
    subscribers: Vec<Box<dyn Subscriber + Send + Sync>>,
}

impl EventDispatcher {
    pub fn new(rx: Receiver<Event>) -> Self {
        Self {
            rx,
            subscribers: Vec::new(),
        }
    }

    /// Adds a subscriber to the broadcast list.
    pub fn add_subscriber(&mut self, sub: Box<dyn Subscriber + Send + Sync>) {
        self.subscribers.push(sub);
    }

    /// Launches the dispatch thread in the background and returns the handle.
    /// It monitors the shutdown_flag to stop processing gracefully.
    pub fn start(self, shutdown_flag: Arc<AtomicBool>) -> JoinHandle<()> {
        thread::spawn(move || {
            log::debug!("EventDispatcher background thread started.");

            // Loop until the shutdown flag is set to true
            while !shutdown_flag.load(Ordering::SeqCst) {
                match self.rx.recv_timeout(Duration::from_millis(100)) {
                    Ok(event) => {
                        // Wrap the event in an Arc once so all interested subscribers
                        // can share the same memory allocation safely.
                        let event_ptr = Arc::new(event);

                        for sub in &self.subscribers {
                            // The dispatcher asks the subscriber if it wants the event.
                            // If true, it hands over the event for processing.
                            if sub.is_interested(&event_ptr) {
                                sub.on_event(&event_ptr);
                            }
                        }
                    }
                    Err(RecvTimeoutError::Timeout) => {
                        // Simply yield and allow the loop to check the shutdown flag again
                        continue;
                    }
                    Err(RecvTimeoutError::Disconnected) => {
                        // The sender side of the channel was dropped.
                        break;
                    }
                }
            }

            log::debug!("Event bus stopped by signal or disconnection. Dispatcher terminating.");
        })
    }
}
