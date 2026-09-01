//! Event router and dispatcher distributing pipeline events to registered listeners.
//!
//! This module provides the [`EventDispatcher`] background worker that reads raw ETW
//! records from the ingestion channel, processes them through the [`Pipeline`](crate::pipeline::Pipeline)
//! engine, and broadcasts assembled [`Event`] objects to all registered [`EventListener`] subscribers.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crate::model::events::{ProcessEvent, SyscallEvent};
use crate::pipeline::engine::Pipeline;
use crate::pipeline::event::Event;
use crate::sensors::etw::EventRecord;

/// The event listener contract defining strongly-typed domain event callbacks.
///
/// Implementors can override specific domain callbacks (e.g. `on_process`, `on_syscall`)
/// or override `on_event` to receive all telemetry events uniformly.
pub trait EventListener: Send + Sync {
    /// Generic dispatch hook invoked for every domain event flowing through the pipeline.
    ///
    /// The default implementation inspects the event variant and forwards it to the
    /// corresponding specialized callback method.
    ///
    /// # Arguments
    ///
    /// * `event` - The domain [`Event`] being dispatched.
    fn on_event(&self, event: &Event) {
        match event {
            Event::Process(process_event) => self.on_process(process_event),
            Event::Syscall(syscall_event) => self.on_syscall(syscall_event),
        }
    }

    /// Called when a process lifecycle or rundown event occurs.
    ///
    /// # Arguments
    ///
    /// * `_event` - The [`ProcessEvent`] details.
    fn on_process(&self, _event: &ProcessEvent) {}

    /// Called when a kernel system call execution event occurs.
    ///
    /// # Arguments
    ///
    /// * `_event` - The [`SyscallEvent`] details.
    fn on_syscall(&self, _event: &SyscallEvent) {}
}

/// Central event dispatcher distributing ingested telemetry across registered analytics listeners.
///
/// Consumes raw [`EventRecord`] items from a channel, passes them through the synchronous
/// [`Pipeline`] engine to resolve stack walks, and broadcasts completed [`Event`] instances
/// to all attached [`EventListener`] sinks.
pub struct EventDispatcher {
    rx: Receiver<EventRecord>,
    listeners: Vec<Box<dyn EventListener>>,
}

impl EventDispatcher {
    /// Creates a new `EventDispatcher` consuming from the specified channel receiver.
    ///
    /// # Arguments
    ///
    /// * `rx` - Channel receiver yielding raw ETW records from sensors.
    ///
    /// # Returns
    ///
    /// An initialized [`EventDispatcher`] with no attached listeners.
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
    /// * `listener` - Boxed [`EventListener`] implementation.
    pub fn add_listener(&mut self, listener: Box<dyn EventListener>) {
        self.listeners.push(listener);
    }

    /// Launches the dispatch routing loop in a background worker thread.
    ///
    /// # Arguments
    ///
    /// * `shutdown_flag` - Atomic flag checked periodically to initiate graceful termination.
    ///
    /// # Returns
    ///
    /// A `JoinHandle` for the spawned background worker thread.
    pub fn start(self, shutdown_flag: Arc<AtomicBool>) -> JoinHandle<()> {
        thread::spawn(move || self.run(shutdown_flag))
    }

    /// Internal worker loop processing records and broadcasting events until shutdown.
    fn run(self, shutdown_flag: Arc<AtomicBool>) {
        log::debug!(target: "dispatcher", "EventDispatcher background thread started.");
        let mut pipeline = Pipeline::new();

        while !shutdown_flag.load(Ordering::Relaxed) {
            match self.rx.recv_timeout(Duration::from_millis(100)) {
                Ok(record) => {
                    if let Some(event) = pipeline.feed(&record) {
                        self.dispatch(&event);
                    }
                }
                Err(RecvTimeoutError::Timeout) => {
                    // Flush any pending events whose stack correlation timed out
                    for expired_event in pipeline.flush_expired() {
                        self.dispatch(&expired_event);
                    }
                }
                Err(RecvTimeoutError::Disconnected) => break,
            }
        }

        log::debug!(target: "dispatcher", "Event bus stopped by signal or disconnection. Dispatcher terminating.");
    }

    /// Dispatches a fully assembled domain event to all registered listeners.
    fn dispatch(&self, event: &Event) {
        for listener in &self.listeners {
            listener.on_event(event);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;
    use std::sync::mpsc;

    use super::*;
    use windows_sys::core::GUID;

    struct MockListener {
        process_count: Arc<AtomicUsize>,
    }

    impl EventListener for MockListener {
        fn on_process(&self, _event: &ProcessEvent) {
            self.process_count.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn create_dummy_process_record() -> EventRecord {
        let mut user_data = Vec::new();
        user_data.extend_from_slice(&(0xAAAA_BBBBusize).to_ne_bytes()); // UniqueProcessKey
        user_data.extend_from_slice(&5555u32.to_ne_bytes());             // ProcessId
        user_data.extend_from_slice(&4u32.to_ne_bytes());                // ParentId
        user_data.extend_from_slice(&1u32.to_ne_bytes());                // SessionId
        user_data.extend_from_slice(&0i32.to_ne_bytes());                // ExitStatus
        user_data.extend_from_slice(&(0x200000usize).to_ne_bytes());     // DirectoryTableBase
        user_data.extend_from_slice(&[1u8, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0]); // SID S-1-5-18
        user_data.extend_from_slice(b"test.exe\0");
        let cmd: Vec<u8> = "test.exe\0".encode_utf16().flat_map(|u| u.to_ne_bytes()).collect();
        user_data.extend_from_slice(&cmd);

        EventRecord {
            provider_id: GUID {
                data1: 0x22fb2cd6,
                data2: 0x0e7b,
                data3: 0x4226,
                data4: [0xa0, 0x66, 0x61, 0x80, 0xf7, 0x71, 0x24, 0x65],
            },
            event_id: 0,
            version: 2,
            opcode: 1, // Start
            level: 0,
            process_id: 5555,
            thread_id: 100,
            timestamp: 50_000,
            user_data,
            stack_trace: None,
        }
    }

    /// Verifies that EventDispatcher properly feeds records through the pipeline and invokes listener callbacks.
    #[test]
    fn test_dispatcher_worker_and_listener_invocation() {
        let (tx, rx) = mpsc::channel();
        let mut dispatcher = EventDispatcher::new(rx);

        let process_count = Arc::new(AtomicUsize::new(0));
        dispatcher.add_listener(Box::new(MockListener {
            process_count: Arc::clone(&process_count),
        }));

        let shutdown_flag = Arc::new(AtomicBool::new(false));
        let handle = dispatcher.start(Arc::clone(&shutdown_flag));

        // Send a record to the dispatcher
        tx.send(create_dummy_process_record()).expect("Send must succeed");

        // Wait briefly for worker to process
        thread::sleep(Duration::from_millis(50));

        // Signal shutdown
        shutdown_flag.store(true, Ordering::SeqCst);
        handle.join().expect("Worker thread must terminate cleanly");

        assert_eq!(process_count.load(Ordering::SeqCst), 1);
    }
}
