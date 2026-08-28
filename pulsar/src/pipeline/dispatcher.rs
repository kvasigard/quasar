//! Event router and dispatcher distributing pipeline events to registered listeners.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crate::model::events::{ProcessEvent, SyscallEvent};
use crate::pipeline::call_stack_correlator::CallStackCorrelator;
use crate::pipeline::Event;
use crate::sensors::etw::EventRecord;

/// The event listener contract defining strongly-typed domain event callbacks.
///
/// Sinks implement only the methods for event types they are interested in.
pub trait EventListener: Send + Sync {
    /// Called when a process lifecycle or rundown event occurs.
    fn on_process(&self, _event: &ProcessEvent) {}

    /// Called when a kernel system call execution event occurs.
    fn on_syscall(&self, _event: &SyscallEvent) {}
}

/// Central event router distributing ingested telemetry across registered analytics listeners.
pub struct EventDispatcher {
    rx: Receiver<EventRecord>,
    listeners: Vec<Box<dyn EventListener>>,
}

impl EventDispatcher {
    /// Creates a new `EventDispatcher` consuming from the specified channel receiver.
    ///
    /// # Arguments
    ///
    /// * `rx` - Channel receiver yielding raw ETW records.
    pub fn new(rx: Receiver<EventRecord>) -> Self {
        Self {
            rx,
            listeners: Vec::new(),
        }
    }

    /// Registers a new event listener sink to receive dispatched events.
    ///
    /// # Arguments
    ///
    /// * `listener` - Boxed listener implementation.
    pub fn add_listener(&mut self, listener: Box<dyn EventListener>) {
        self.listeners.push(listener);
    }

    /// Fast-path check to determine if an ETW record is an NT Kernel Logger Process event.
    #[inline]
    fn is_process_event(record: &EventRecord) -> bool {
        // Process Class GUID: 22fb2cd6-0e7b-4226-a066-6180f7712465
        record.provider_id.data1 == 0x22fb2cd6
            && matches!(record.opcode, 1 | 2 | 3 | 4 | 39)
    }

    /// Fast-path check to determine if an ETW record is an NT Kernel Logger Syscall event.
    #[inline]
    fn is_syscall_event(record: &EventRecord) -> bool {
        // PERFINFO_GUID: CE1DBFB4-39EA-4851-89E0-A77CBFCCE4ED
        record.provider_id.data1 == 0xce1dbfb4 && record.opcode == 51
    }

    /// Fast-path check to determine if an ETW record is an asynchronous NT Kernel StackWalk event.
    #[inline]
    fn is_stack_walk_event(record: &EventRecord) -> bool {
        // StackWalkGuid: DEF2FE46-7BD6-4B80-BD94-F57FE20D0CE3
        record.provider_id.data1 == 0xdef2fe46 && record.opcode == 32
    }

    /// Dispatches a fully formed domain event to all interested registered listeners.
    fn dispatch_event(&self, event: &Event) {
        match event {
            Event::Process(process_event) => {
                for listener in &self.listeners {
                    listener.on_process(process_event);
                }
            }
            Event::Syscall(syscall_event) => {
                for listener in &self.listeners {
                    listener.on_syscall(syscall_event);
                }
            }
        }
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
            let mut correlator = CallStackCorrelator::new();

            while !shutdown_flag.load(Ordering::SeqCst) {
                match self.rx.recv_timeout(Duration::from_millis(100)) {
                    Ok(record) => {
                        if Self::is_stack_walk_event(&record) {
                            if let Some(event) = correlator.process_stack_walk(&record) {
                                self.dispatch_event(&event);
                            }
                        } else if Self::is_syscall_event(&record) {
                            match SyscallEvent::try_from(&record) {
                                Ok(syscall_event) => {
                                    let event = Event::Syscall(syscall_event);

                                    // If record already carries an inline stack trace from user-mode ETW or driver, bypass correlator
                                    if record.stack_trace.is_some() {
                                        self.dispatch_event(&event);
                                    } else if let Some(ready_event) = correlator.process_trigger(event, true) {
                                        self.dispatch_event(&ready_event);
                                    }
                                }
                                Err(err) => {
                                    log::warn!(
                                        target: "dispatcher",
                                        "Failed to parse SyscallEvent: {}",
                                        err
                                    );
                                }
                            }
                        } else if Self::is_process_event(&record) {
                            match ProcessEvent::try_from(&record) {
                                Ok(process_event) => {
                                    let event = Event::Process(process_event);

                                    // Process events without asynchronous stack tracing bypass the correlator
                                    if let Some(ready_event) = correlator.process_trigger(event, false) {
                                        self.dispatch_event(&ready_event);
                                    }
                                }
                                Err(err) => {
                                    log::warn!(
                                        target: "dispatcher",
                                        "Failed to parse ProcessEvent: {}",
                                        err
                                    );
                                }
                            }
                        }
                    }
                    Err(RecvTimeoutError::Timeout) => {
                        // Periodic eviction check for timed-out async stack walks
                        for expired_event in correlator.flush_expired() {
                            self.dispatch_event(&expired_event);
                        }
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



