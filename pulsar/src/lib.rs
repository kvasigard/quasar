//! Core library for the Singularity EDR agent.

pub mod comm;
pub mod drivers;
pub mod error;
pub mod helpers;
pub mod pipeline;
pub mod sensors;
pub mod sinks;

// Re-export the primary error type for easy access across the crate.
pub use error::AppError;
