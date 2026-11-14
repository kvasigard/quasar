//! Event Tracing for Windows (ETW) sensor subsystem, System Logger V2 session management,
//! and zero-copy callback routing.
//!
//! # Architecture & Data Flow
//!
//! This module forms the user-mode telemetry ingestion boundary of Quasar (`pulsar`). It
//! configures, starts, and consumes real-time Windows ETW sessions with zero dependencies on
//! upper-layer analytical schemas or domain models (`crate::pipeline` or `crate::model`).
//!
//! The end-to-end data flow through this subsystem proceeds in four stages:
//!
//! 1. **Session Configuration ([`SessionDirector`](director::SessionDirector), [`KernelSessionBuilder`], [`UserSessionBuilder`]):**
//!    Callers construct either a System Logger V2 kernel session (configured via a 256-bit
//!    [`PerfGroupMask`] and batch stack-walk hooks) or a manifest/TraceLogging user session
//!    (configured via [`Provider`] descriptors and kernel-side [`ProviderFilter`]s).
//! 2. **Kernel Control & Buffer Allocation ([`TracePropertiesBuffer`], [`EtwSession`]):**
//!    Starting a session allocates an 8-byte-aligned `EVENT_TRACE_PROPERTIES` or
//!    `EVENT_TRACE_PROPERTIES_V2` block, registers the session with Windows (`StartTraceW`),
//!    and applies extended kernel flags (`TraceSetInformation`) or provider filters
//!    (`EnableTraceEx2`) inside the OS kernel before events ever reach user-mode.
//! 3. **Zero-Copy Callback Ingestion ([`RawEvent`], [`TraceContext`]):**
//!    [`EtwSession::consume_with_router`] spawns a dedicated background worker thread running
//!    the blocking Win32 `ProcessTrace` loop. For every event delivered to the C-ABI callback,
//!    the raw `EVENT_RECORD` pointer is cast to a zero-copy `#[repr(transparent)]` [`RawEvent`]
//!    reference valid for the callback's duration—eliminating per-event heap allocations.
//! 4. **Decoupled Routing & Batch Metrics ([`TraceRouter`], [`ConsumerHandle`], [`ConsumerMetrics`]):**
//!    The callback invokes [`TraceRouter::on_event`] inside a `catch_unwind` FFI guard.
//!    Thread-local event outcomes ([`ConsumerOutcome`]) are accumulated without atomic bus
//!    contention and flushed in batches once per ETW buffer inside `BufferCallback`.

pub mod director;
pub mod error;
pub mod filter;
pub mod masks;
pub mod raw_event;
pub mod router;

mod consumer;
mod event;
mod kernel;
mod properties;
mod provider;
mod session;
mod user;

pub use consumer::{ConsumerHandle, TraceContext};
pub use error::EtwError;
pub use event::EventRecord;
pub use filter::{EventIdFilter, ProviderFilter};
pub use kernel::{KernelFlag, KernelSession, KernelSessionBuilder};
pub use masks::PerfGroupMask;
pub use properties::{TracePropertiesBuffer, TraceStatistics};
pub use provider::{Provider, TraceLevel};
pub use raw_event::{RawEvent, SyntheticEvent};
pub use router::{ConsumerMetrics, ConsumerMetricsSnapshot, ConsumerOutcome, TraceRouter};
pub use session::{EtwSession, EtwSessionBuilder, EventTraceProperties};
pub use user::{UserSession, UserSessionBuilder};
