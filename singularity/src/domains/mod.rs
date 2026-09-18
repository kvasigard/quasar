//! Functional security and telemetry domains for the Singularity driver.
//!
//! Each subdomain represents an independent capability with its own error types,
//! operational logic, and state guards.

pub mod anti_tampering;
pub mod callbacks;
