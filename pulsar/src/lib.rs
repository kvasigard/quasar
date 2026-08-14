//! Core library for the Singularity EDR agent.

pub mod bootstrap;
pub mod comm;
pub mod context;
pub mod drivers;
pub mod error;
pub mod helpers;
pub mod pipeline;
pub mod sensors;
pub mod sinks;

pub use error::AppError;
