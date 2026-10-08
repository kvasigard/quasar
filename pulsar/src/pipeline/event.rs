//! Unified pipeline event definitions, decoding, and dispatching.
//!
//! This module defines the central [`Event`] enum representing all normalized telemetry
//! flowing through the Pulsar analytics engine. Pulsar ingests events from two distinct
//! high-performance telemetry sources:
//!
//! ```text
//!  +-----------------------------------+     +-----------------------------------+
//!  |      Windows ETW Kernel Trace     |     |   Singularity KMDF Kernel Driver  |
//!  | (Process, Thread, Syscall, Stack) |     |  (ObRegisterCallbacks, Tampering) |
//!  +-----------------+-----------------+     +-----------------+-----------------+
//!                    |                                         |
//!                    v                                         v
//!         [ETW Session & Consumer]                  [Per-CPU Ring Buffer]
//!                    |                                         |
//!                    v                                         v
//!         Event::from_record()                       DriverSensor::drain_all()
//!                    |                                         |
//!                    +--------------------+--------------------+
//!                                         |
//!                                         v
//!                             enum Event { ... }
//!                                         |
//!                                         v
//!                             [EventDispatcher Worker]
//!                                         |
//!                                         v
//!                       EventListener::on_event(&self, event)
//!                                         |
//!                     +-------------------+-------------------+
//!                     |                   |                   |
//!                     v                   v                   v
//!               on_process()         on_syscall()       on_handle_pre_op()
//!                     |                   |                   |
//!                     +-------------------+-------------------+
//!                                         |
//!                                         v
//!                              [Analytics & Detection Sinks]
//! ```
//!
//! ---
//!
//! # Adding a New Telemetry Event to Pulsar
//!
//! Depending on whether the event originates from **ETW** or the **Kernel Driver**, follow the corresponding workflow:
//!
//! ## Path A: Adding an ETW-Sourced Event
//!
//! ### Step 1: Define the Binary DTO Schema (`pulsar/src/pipeline/etw_schemas/`)
//! Define the zero-copy C-compatible layout in `etw_schemas/nt_kernel/<domain>.rs` implementing `TryFrom<&[u8]>`:
//! ```rust,ignore
//! #[repr(C)]
//! pub struct ImageLoadV2Dto {
//!     pub image_base: u64,
//!     pub image_size: u64,
//!     pub process_id: u32,
//!     pub image_checksum: u32,
//! }
//!
//! impl<'a> TryFrom<&'a [u8]> for &'a ImageLoadV2Dto {
//!     type Error = EtwSchemaError;
//!     fn try_from(slice: &'a [u8]) -> Result<Self, Self::Error> {
//!         if slice.len() < core::mem::size_of::<ImageLoadV2Dto>() {
//!             return Err(EtwSchemaError::TruncatedPayload);
//!         }
//!         Ok(unsafe { &*(slice.as_ptr() as *const ImageLoadV2Dto) })
//!     }
//! }
//! ```
//!
//! ### Step 2: Define the Domain Model (`pulsar/src/model/events/`)
//! Define the strongly-typed domain struct in `model/events/<domain>.rs` implementing `TryFrom<&EventRecord>`:
//! ```rust,ignore
//! #[derive(Debug, Clone, PartialEq, Eq)]
//! pub struct ImageLoadEvent {
//!     pub timestamp: i64,
//!     pub process_id: u32,
//!     pub image_base: u64,
//!     pub file_name: String,
//!     pub stack_trace: Option<StackTrace>,
//! }
//!
//! impl TryFrom<&EventRecord> for ImageLoadEvent {
//!     type Error = EtwSchemaError;
//!     fn try_from(record: &EventRecord) -> Result<Self, Self::Error> {
//!         let dto: &ImageLoadV2Dto = record.user_data().try_into()?;
//!         let (file_name, _) = extract_utf16_string(record.user_data(), 24);
//!         Ok(Self {
//!             timestamp: record.timestamp,
//!             process_id: dto.process_id,
//!             image_base: dto.image_base,
//!             file_name: file_name.unwrap_or_default(),
//!             stack_trace: None,
//!         })
//!     }
//! }
//! ```
//!
//! ### Step 3: Register Variant in [`Event`]
//! Add the new variant to the enum in this file:
//! ```rust,ignore
//! pub enum Event {
//!     Process(ProcessEvent),
//!     Syscall(SyscallEvent),
//!     HandlePreOp(HandlePreOpEvent),
//!     ImageLoad(ImageLoadEvent), // <--- New variant
//! }
//! ```
//!
//! ### Step 4: Register in [`Event::from_record`]
//! Add a match arm mapping `(PROVIDER_GUID_DATA1, OPCODE)` to decode the record and indicate whether
//! asynchronous kernel stack correlation is needed:
//! ```rust,ignore
//! (NT_KERNEL_IMAGE_LOAD_PROVIDER_GUID_DATA1, image_load_opcodes::LOAD) => {
//!     ImageLoadEvent::try_from(record)
//!         .ok()
//!         .map(|e| (Event::ImageLoad(e), true))
//! }
//! ```
//!
//! ### Step 5: Update [`EventListener`](crate::pipeline::EventListener)
//! Add `fn on_image_load(&self, _event: &ImageLoadEvent) {}` to the trait, and route `Event::ImageLoad` in `on_event`.
//!
//! ---
//!
//! ## Path B: Adding a Driver Ring Buffer-Sourced Event
//!
//! ### Step 1: Define Driver Event Contract (`shared/src/ring_buffer/events/<domain>.rs`)
//! Create a dedicated submodule under `shared/src/ring_buffer/events/` and implement [`TemplateEvent`](shared::ring_buffer::TemplateEvent)
//! (or [`DriverEvent`](shared::ring_buffer::DriverEvent) for dynamic length payloads):
//! ```rust,ignore
//! #[repr(C)]
//! #[derive(Debug, Clone, Copy, PartialEq, Eq)]
//! pub struct ProcessCreateEvent {
//!     pub parent_pid: u32,
//!     pub child_pid: u32,
//!     pub image_path: [u8; 260],
//! }
//!
//! impl TemplateEvent for ProcessCreateEvent {
//!     const EVENT_TYPE: DriverEventType = DriverEventType::ProcessCreate;
//! }
//! ```
//!
//! ### Step 2: Register Variant in [`Event`]
//! Add the new variant to the enum in this file:
//! ```rust,ignore
//! pub enum Event {
//!     Process(ProcessEvent),
//!     Syscall(SyscallEvent),
//!     HandlePreOp(HandlePreOpEvent),
//!     ProcessCreate(ProcessCreateEvent), // <--- New driver variant
//! }
//! ```
//!
//! ### Step 3: Decode in Driver Sensor (`pulsar/src/sensors/driver/sensor.rs`)
//! In `DriverSensor::start`, add a decoding arm in `ring_manager.drain_all`:
//! ```rust,ignore
//! if event_type == DriverEventType::ProcessCreate as u16 {
//!     if payload.len() >= core::mem::size_of::<ProcessCreateEvent>() {
//!         // Zero-copy read from unaligned ring buffer slice
//!         let event = unsafe { core::ptr::read_unaligned(payload.as_ptr() as *const ProcessCreateEvent) };
//!         event_callback(Event::ProcessCreate(event));
//!     }
//! }
//! ```
//!
//! ### Step 4: Update [`EventListener`](crate::pipeline::EventListener)
//! Add `fn on_process_create(&self, _event: &ProcessCreateEvent) {}` to the trait, and route `Event::ProcessCreate` in `on_event`.
//!
//! ---
//!
//! ### Decoding an ETW Event Record
//!
//! ```no_run
//! use pulsar::pipeline::Event;
//! use pulsar::sensors::etw::EventRecord;
//!
//! # fn example(record: &EventRecord) {
//! if let Some((event, requires_stack_correlation)) = Event::from_record(record) {
//!     println!("Parsed event timestamp: {}", event.timestamp());
//!     if requires_stack_correlation {
//!         println!("Event queued for asynchronous kernel call stack correlation.");
//!     }
//! }
//! # }
//! ```
//!
//! ### Consuming Pipeline Events in an Analytical Sink
//!
//! ```no_run
//! use pulsar::pipeline::Event;
//!
//! fn analyze_event(event: &Event) {
//!     match event {
//!         Event::Process(proc) => {
//!             println!("Process Lifecycle: PID {} -> Image: {}", proc.process_id, proc.image_file_name);
//!         }
//!         Event::Syscall(sys) => {
//!             println!("Syscall Execution: Address {:#X} from PID {}", sys.syscall_address, sys.process_id);
//!         }
//!         Event::HandlePreOp(handle) => {
//!             println!(
//!                 "Driver Alert: Process PID {} opened handle to Target PID {} (Access: {:#010X})",
//!                 handle.source_pid, handle.target_pid, handle.desired_access
//!             );
//!         }
//!     }
//! }
//! ```

use shared::ring_buffer::HandlePreOpEvent;

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

    /// Pre-operation handle creation or duplication intercepted by kernel driver callbacks.
    HandlePreOp(HandlePreOpEvent),
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
            Event::HandlePreOp(_) => 0,
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
            Event::HandlePreOp(_) => {}
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
