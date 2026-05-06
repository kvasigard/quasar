//! Telemetry ingestion and domain-specific event parsing.
//!
//! A "sensor" represents a distinct source of system telemetry, such as ETW 
//! traces, file I/O operations, or network connections. 
//!
//! The `sensors` module is responsible for consuming raw data streams—often 
//! utilizing the transports defined in the `comm` module—and parsing OS-specific 
//! or driver-specific structures. Each sensor translates its raw input into 
//! normalized, unified events that are then forwarded to the analysis pipeline.

pub mod etw;
