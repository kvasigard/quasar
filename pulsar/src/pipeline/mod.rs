//! Telemetry ingestion, zero-copy decoding, asynchronous stack correlation, and priority-aware
//! event dispatching pipeline.
//!
//! # End-to-End Pipeline Data Flow
//!
//! ```text
//!  ┌─────────────────────────────────────────────────────────────────────┐
//!  │ Win32 ProcessTrace Callback (`sensors::etw::consumer`)              │
//!  │   &RawEvent -> PipelineEventRouter::on_event (Zero-Copy Decoding)   │
//!  └──────────────┬───────────────────────────────────────┬──────────────┘
//!                 │                                       │
//!    (Tier 1: High-Priority State)           (Tier 3: Correlated Telemetry)
//!      `state_tx: SyncSender<Event>`      `telemetry_tx: SyncSender<TelemetryEnvelope>`
//!                 │                                       │
//!                 ▼                                       ▼
//!  ┌─────────────────────────────────────────────────────────────────────┐
//!  │ EventDispatcher Worker Thread (`pulsar-dispatcher`)                 │
//!  │   1. Drain `state_rx` (Process Start/DCStart/End)  ──► Sinks        │
//!  │   2. Drain `driver_rx` (Kernel Per-CPU Ring Buffer)──► Sinks        │
//!  │   3. Drain `telemetry_rx` ──► Pipeline / CallStackCorrelator ──► Sinks │
//!  └─────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! 1. **In-Callback Decoding & Priority Split ([`PipelineEventRouter`]):**
//!    Implements [`TraceRouter`](crate::sensors::etw::TraceRouter) to inspect `&RawEvent` headers
//!    inside the ETW callback, decode matching binary payloads via [`ByteCursor`](etw_schemas::ByteCursor)
//!    without intermediate `Vec<u8>` allocations, and split state-building lifecycle events
//!    (`state_tx`) from stack-correlated telemetry (`telemetry_tx`).
//! 2. **Asynchronous Stack Correlation ([`Pipeline`], [`CallStackCorrelator`]):**
//!    Because the Windows System Logger / NT Kernel Logger emits kernel call stacks as separate
//!    out-of-band `StackWalk_TypeGroup1` (Opcode 32) events, [`CallStackCorrelator`] pairs
//!    [`TelemetryEnvelope::Trigger`] events with [`TelemetryEnvelope::StackWalk`] frames using
//!    the composite key `(EventTimeStamp, ProcessId, ThreadId)` and evicts timed-out entries.
//! 3. **Priority-Aware Dispatching ([`EventDispatcher`], [`EventListener`]):**
//!    Drains `state_rx` first so `ProcessContextSink` updates the in-memory process tree before
//!    kernel driver alerts (`driver_rx`) or syscall telemetry (`telemetry_rx`) are evaluated by
//!    `DetectionSink`.

pub mod call_stack_correlator;
pub mod constants;
pub mod dispatcher;
pub mod engine;
pub mod etw_schemas;
pub mod event;
pub mod router;

pub use call_stack_correlator::CallStackCorrelator;
pub use dispatcher::{EventDispatcher, EventListener};
pub use engine::Pipeline;
pub use event::Event;
pub use router::{PipelineEventRouter, TelemetryEnvelope};
