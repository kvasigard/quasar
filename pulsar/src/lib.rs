//! Core library for the Singularity EDR agent.

pub mod bootstrap;
pub mod cli;
pub mod context;
pub mod drivers;
pub mod error;
pub mod helpers;
pub mod pipeline;
pub mod profiling;
pub mod sensors;
pub mod sinks;

pub use error::{AppError, BootstrapError, DriverError, EtwError, HandlerError, Win32Error};
pub use profiling::{init_profiling, ProfilingGuard};
