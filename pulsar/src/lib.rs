//! Core library for the Singularity EDR agent.

pub mod bootstrap;
pub mod drivers;
pub mod error;
pub mod helpers;
pub mod model;
pub mod pipeline;
pub mod sensors;
pub mod sinks;

pub use error::AppError;
