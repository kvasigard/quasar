//! Pipeline event definitions and ingestion decoding.
//!
//! This module defines the unified [`Event`] domain enumeration flowing through the
//! Pulsar analytics and detection pipeline, along with decoding logic from raw ETW records.
//!
//! # Adding a New Telemetry Event to the Pipeline
//!
//! 1. **Define the Binary DTO Schema (`pipeline/etw_schemas/`)**:
//!    Define the zero-copy C-compatible struct representing the raw payload emitted by the ETW provider
//!    (e.g., `ImageLoad_TypeGroup1` or `FileIo_TypeGroup1`) in `crate::pipeline::etw_schemas::nt_kernel::<module>`
//!    implementing `TryFrom<&[u8]>`.
//!
//! 2. **Define the Domain Event Model (`model/events/`)**:
//!    Create the high-level, strongly-typed domain struct in `crate::model::events::<event_name>` (e.g. `ImageLoadEvent`)
//!    implementing `TryFrom<&EventRecord>` by parsing the schema DTO.
//!
//! 3. **Register the Event in this Enum**:
//!    Add the new variant to the [`Event`] enum below (e.g. `ImageLoad(ImageLoadEvent)`).
//!
//! 4. **Declare Provider Constants**:
//!    Add the provider's GUID `data1` and opcodes to [`crate::pipeline::constants`].
//!
//! 5. **Add Match Arm to [`Event::from_record`]**:
//!    Add an arm mapping `(PROVIDER_GUID_DATA1, OPCODE)` to parse the event and specify whether
//!    asynchronous kernel call stack correlation is required (`true` if kernel stack walking is configured,
//!    `false` if stack correlation is unneeded or already inline).
//!
//! 6. **Update [`EventListener`](crate::pipeline::EventListener)**:
//!    Add a callback method (e.g. `fn on_image_load(&self, _event: &ImageLoadEvent) {}`) to the listener
//!    trait, and route the new variant in its default `on_event` implementation.

use crate::model::events::{ProcessEvent, SyscallEvent};
use crate::model::types::StackTrace;
use crate::pipeline::constants::*;
use crate::sensors::etw::EventRecord;

/// Strongly-typed domain events flowing through the analytics pipeline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// Process lifecycle change or telemetry event.
    Process(ProcessEvent),

    /// Kernel system call execution event.
    Syscall(SyscallEvent),
}

impl Event {
    /// Returns the timestamp of this domain event.
    ///
    /// # Returns
    ///
    /// The 64-bit integer timestamp (QPC or FileTime) when the event occurred.
    pub fn timestamp(&self) -> i64 {
        match self {
            Event::Process(e) => e.timestamp,
            Event::Syscall(e) => e.timestamp,
        }
    }

    /// Attaches or updates the call stack trace for this domain event.
    ///
    /// # Arguments
    ///
    /// * `stack_trace` - The resolved instruction pointer call stack to attach.
    pub fn attach_stack_trace(&mut self, stack_trace: StackTrace) {
        match self {
            Event::Process(e) => e.stack_trace = Some(stack_trace),
            Event::Syscall(e) => e.stack_trace = Some(stack_trace),
        }
    }

    /// Attempts to decode a raw ETW record into a domain [`Event`] and indicates
    /// whether the event requires asynchronous kernel stack trace correlation.
    ///
    /// # Arguments
    ///
    /// * `record` - The raw [`EventRecord`] received from the ETW sensor.
    ///
    /// # Returns
    ///
    /// `Some((Event, requires_async_stack))` if the record matches a registered telemetry
    /// provider and opcode, or `None` if the event is unmonitored or failed parsing.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use pulsar::pipeline::Event;
    /// use pulsar::sensors::etw::EventRecord;
    ///
    /// # fn example(record: &EventRecord) {
    /// if let Some((event, requires_stack)) = Event::from_record(record) {
    ///     println!("Decoded event at timestamp {}: requires stack = {}", event.timestamp(), requires_stack);
    /// }
    /// # }
    /// ```
    pub fn from_record(record: &EventRecord) -> Option<(Self, bool)> {
        match (record.provider_id.data1, record.opcode) {
            // Process Start / End / DCStart / DCEnd / Defunct (Async stack correlation not required)
            (
                NT_KERNEL_PROCESS_PROVIDER_GUID_DATA1,
                process_opcodes::START
                | process_opcodes::END
                | process_opcodes::DC_START
                | process_opcodes::DC_END
                | process_opcodes::DEFUNCT,
            ) => ProcessEvent::try_from(record)
                .ok()
                .map(|e| (Event::Process(e), false)),

            // Syscall Enter (Requires asynchronous kernel stack walk correlation)
            (NT_KERNEL_PERFINFO_PROVIDER_GUID_DATA1, syscall_opcodes::SYSCALL_ENTER) => {
                SyscallEvent::try_from(record)
                    .ok()
                    .map(|e| (Event::Syscall(e), true))
            }

            // Unrecognized or unmonitored provider/opcode
            _ => None,
        }
    }
}
