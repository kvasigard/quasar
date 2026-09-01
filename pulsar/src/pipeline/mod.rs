//! The event routing backbone of the EDR.
//!
//! This module provides the telemetry ingestion, decoding, stack correlation,
//! and event dispatching pipeline for Pulsar.

pub mod call_stack_correlator;
pub mod constants;
pub mod dispatcher;
pub mod engine;
pub mod etw_schemas;
pub mod event;

pub use call_stack_correlator::CallStackCorrelator;
pub use dispatcher::{EventDispatcher, EventListener};
pub use engine::Pipeline;
pub use event::Event;
