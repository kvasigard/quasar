//! Priority-aware event dispatcher distributing pipeline events to registered listeners.
//!
//! [`EventDispatcher`] enforces a strict three-tier priority draining order so that process
//! state updates (`state_rx`) are always applied to `SystemState` / `ProcessTree` before
//! kernel driver ring-buffer alerts (`driver_rx`) or high-volume telemetry (`telemetry_rx`)
//! are evaluated by detection sinks.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use shared::ring_buffer::LsassAccessEvent;

use crate::model::events::{ProcessEvent, SyscallEvent};
use crate::pipeline::engine::Pipeline;
use crate::pipeline::event::Event;
use crate::pipeline::router::TelemetryEnvelope;
use crate::sensors::etw::EventRecord;

/// The event listener contract defining strongly-typed domain event callbacks.
pub trait EventListener: Send + Sync {
    /// Generic dispatch hook invoked for every domain event flowing through the pipeline.
    fn on_event(&self, event: &Event) {
        match event {
            Event::Process(process_event) => self.on_process(process_event),
            Event::Syscall(syscall_event) => self.on_syscall(syscall_event),
            Event::LsassAccess(lsass_event) => self.on_lsass_access(lsass_event),
        }
    }

    /// Called when a process lifecycle or rundown event occurs.
    fn on_process(&self, _event: &ProcessEvent) {}

    /// Called when a kernel system call execution event occurs.
    fn on_syscall(&self, _event: &SyscallEvent) {}

    /// Called when an unauthorized or sensitive handle operation targeting `lsass.exe` is intercepted.
    fn on_lsass_access(&self, _event: &LsassAccessEvent) {}
}

enum EtwInput {
    /// Priority-split zero-copy channels driven by [`PipelineEventRouter`](crate::pipeline::PipelineEventRouter).
    PrioritySplit {
        state_rx: Receiver<Event>,
        telemetry_rx: Receiver<TelemetryEnvelope>,
    },
    /// Legacy single-channel raw [`EventRecord`] receiver.
    RawRecords(Receiver<EventRecord>),
}

/// Central event dispatcher distributing ingested telemetry across registered analytics listeners.
pub struct EventDispatcher {
    input: EtwInput,
    driver_rx: Option<Receiver<Event>>,
    listeners: Vec<Box<dyn EventListener>>,
}

impl EventDispatcher {
    /// Creates a new `EventDispatcher` consuming from priority-split zero-copy channels
    /// (`state_rx` for high-priority `Process` state events, `telemetry_rx` for stack-correlated telemetry).
    pub fn with_priority_channels(
        state_rx: Receiver<Event>,
        telemetry_rx: Receiver<TelemetryEnvelope>,
    ) -> Self {
        Self {
            input: EtwInput::PrioritySplit {
                state_rx,
                telemetry_rx,
            },
            driver_rx: None,
            listeners: Vec::new(),
        }
    }

    /// Creates a new `EventDispatcher` consuming raw [`EventRecord`] items from a single channel.
    pub fn new(etw_rx: Receiver<EventRecord>) -> Self {
        Self {
            input: EtwInput::RawRecords(etw_rx),
            driver_rx: None,
            listeners: Vec::new(),
        }
    }

    /// Attaches an auxiliary receiver for events originating from the kernel driver ring buffer sensor.
    pub fn with_driver_receiver(mut self, driver_rx: Receiver<Event>) -> Self {
        self.driver_rx = Some(driver_rx);
        self
    }

    /// Registers a new event listener sink to receive dispatched events.
    pub fn add_listener(&mut self, listener: Box<dyn EventListener>) {
        self.listeners.push(listener);
    }

    /// Launches the dispatch routing loop in a named background worker thread.
    pub fn start(self, shutdown_flag: Arc<AtomicBool>) -> JoinHandle<()> {
        thread::Builder::new()
            .name("pulsar-dispatcher".to_string())
            .spawn(move || self.run(shutdown_flag))
            .expect("Failed to spawn pulsar-dispatcher thread")
    }

    fn run(self, shutdown_flag: Arc<AtomicBool>) {
        log::debug!(target: "dispatcher", "EventDispatcher background thread started.");
        let mut pipeline = Pipeline::new();
        let mut last_flush = Instant::now();

        while !shutdown_flag.load(Ordering::Relaxed) {
            let mut processed_any = false;

            match &self.input {
                EtwInput::PrioritySplit {
                    state_rx,
                    telemetry_rx,
                } => {
                    // Tier 1: High-priority state events (Process::Start/DCStart/End)
                    for _ in 0..2048 {
                        match state_rx.try_recv() {
                            Ok(event) => {
                                processed_any = true;
                                self.dispatch(&event);
                            }
                            Err(_) => break,
                        }
                    }

                    // Tier 2: Kernel driver ring-buffer alerts
                    if let Some(ref driver_rx) = self.driver_rx {
                        for _ in 0..512 {
                            match driver_rx.try_recv() {
                                Ok(event) => {
                                    processed_any = true;
                                    self.dispatch(&event);
                                }
                                Err(_) => break,
                            }
                        }
                    }

                    // Tier 3: Stack-correlated telemetry and StackWalk events
                    for _ in 0..2048 {
                        match telemetry_rx.try_recv() {
                            Ok(envelope) => {
                                processed_any = true;
                                if let Some(event) = pipeline.feed_envelope(envelope) {
                                    self.dispatch(&event);
                                }
                            }
                            Err(_) => break,
                        }
                    }

                    if !pipeline.is_correlator_empty()
                        && last_flush.elapsed() >= Duration::from_millis(25)
                    {
                        for expired_event in pipeline.flush_expired() {
                            self.dispatch(&expired_event);
                        }
                        last_flush = Instant::now();
                    }

                    if !processed_any {
                        match state_rx.recv_timeout(Duration::from_millis(5)) {
                            Ok(event) => self.dispatch(&event),
                            Err(RecvTimeoutError::Timeout) => {
                                if !pipeline.is_correlator_empty() {
                                    for expired_event in pipeline.flush_expired() {
                                        self.dispatch(&expired_event);
                                    }
                                    last_flush = Instant::now();
                                }
                            }
                            Err(RecvTimeoutError::Disconnected) => break,
                        }
                    }
                }
                EtwInput::RawRecords(etw_rx) => {
                    for _ in 0..2048 {
                        match etw_rx.try_recv() {
                            Ok(record) => {
                                processed_any = true;
                                if let Some(event) = pipeline.feed(&record) {
                                    self.dispatch(&event);
                                }
                            }
                            Err(_) => break,
                        }
                    }

                    if let Some(ref driver_rx) = self.driver_rx {
                        for _ in 0..512 {
                            match driver_rx.try_recv() {
                                Ok(event) => {
                                    processed_any = true;
                                    self.dispatch(&event);
                                }
                                Err(_) => break,
                            }
                        }
                    }

                    if !pipeline.is_correlator_empty()
                        && last_flush.elapsed() >= Duration::from_millis(25)
                    {
                        for expired_event in pipeline.flush_expired() {
                            self.dispatch(&expired_event);
                        }
                        last_flush = Instant::now();
                    }

                    if !processed_any {
                        match etw_rx.recv_timeout(Duration::from_millis(5)) {
                            Ok(record) => {
                                if let Some(event) = pipeline.feed(&record) {
                                    self.dispatch(&event);
                                }
                            }
                            Err(RecvTimeoutError::Timeout) => {
                                if !pipeline.is_correlator_empty() {
                                    for expired_event in pipeline.flush_expired() {
                                        self.dispatch(&expired_event);
                                    }
                                    last_flush = Instant::now();
                                }
                            }
                            Err(RecvTimeoutError::Disconnected) => break,
                        }
                    }
                }
            }
        }

        // Final sweep on shutdown so no queued state or driver events are lost
        match &self.input {
            EtwInput::PrioritySplit {
                state_rx,
                telemetry_rx,
            } => {
                while let Ok(event) = state_rx.try_recv() {
                    self.dispatch(&event);
                }
                while let Ok(envelope) = telemetry_rx.try_recv() {
                    if let Some(event) = pipeline.feed_envelope(envelope) {
                        self.dispatch(&event);
                    }
                }
            }
            EtwInput::RawRecords(etw_rx) => {
                while let Ok(record) = etw_rx.try_recv() {
                    if let Some(event) = pipeline.feed(&record) {
                        self.dispatch(&event);
                    }
                }
            }
        }

        if let Some(ref driver_rx) = self.driver_rx {
            while let Ok(event) = driver_rx.try_recv() {
                self.dispatch(&event);
            }
        }
        for expired_event in pipeline.flush_expired() {
            self.dispatch(&expired_event);
        }

        log::debug!(target: "dispatcher", "Event bus stopped by signal or disconnection. Dispatcher terminating.");
    }

    /// Dispatches a fully assembled domain event to all registered listeners.
    #[inline]
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
        lsass_count: Arc<AtomicUsize>,
    }

    impl EventListener for MockListener {
        fn on_process(&self, _event: &ProcessEvent) {
            self.process_count.fetch_add(1, Ordering::SeqCst);
        }

        fn on_lsass_access(&self, _event: &LsassAccessEvent) {
            self.lsass_count.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn test_dispatcher_worker_and_listener_invocation() {
        let (tx, rx) = mpsc::channel();
        let (driver_tx, driver_rx) = mpsc::channel();
        let mut dispatcher = EventDispatcher::new(rx).with_driver_receiver(driver_rx);

        let process_count = Arc::new(AtomicUsize::new(0));
        let lsass_count = Arc::new(AtomicUsize::new(0));

        dispatcher.add_listener(Box::new(MockListener {
            process_count: Arc::clone(&process_count),
            lsass_count: Arc::clone(&lsass_count),
        }));

        let shutdown_flag = Arc::new(AtomicBool::new(false));
        let handle = dispatcher.start(Arc::clone(&shutdown_flag));

        let mut user_data = Vec::new();
        user_data.extend_from_slice(&(0xAAAA_BBBBusize).to_ne_bytes()); // UniqueProcessKey
        user_data.extend_from_slice(&1234u32.to_ne_bytes()); // ProcessId
        user_data.extend_from_slice(&4u32.to_ne_bytes()); // ParentId
        user_data.extend_from_slice(&1u32.to_ne_bytes()); // SessionId
        user_data.extend_from_slice(&0i32.to_ne_bytes()); // ExitStatus
        user_data.extend_from_slice(&(0x200000usize).to_ne_bytes()); // DirectoryTableBase
        user_data.extend_from_slice(&[1u8, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0]); // SID S-1-5-18
        user_data.extend_from_slice(b"test.exe\0");
        let cmd: Vec<u8> = "test.exe\0"
            .encode_utf16()
            .flat_map(|u| u.to_ne_bytes())
            .collect();
        user_data.extend_from_slice(&cmd);

        let record = EventRecord {
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
            process_id: 1234,
            thread_id: 100,
            timestamp: 100_000,
            user_data,
            stack_trace: None,
        };

        tx.send(record).unwrap();

        let lsass_event =
            LsassAccessEvent::new(5000, 816, 0x1FFFFF, 0x1000, 0x3000, 1, 0, 1, b"malware.exe");
        driver_tx.send(Event::LsassAccess(lsass_event)).unwrap();

        std::thread::sleep(Duration::from_millis(150));

        shutdown_flag.store(true, Ordering::SeqCst);
        handle.join().unwrap();

        assert_eq!(process_count.load(Ordering::SeqCst), 1);
        assert_eq!(lsass_count.load(Ordering::SeqCst), 1);
    }
}
