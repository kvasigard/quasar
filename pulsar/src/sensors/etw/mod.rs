//! ETW (Event Tracing for Windows) sensor implementation.

pub mod director;

mod event;
mod kernel;
mod session;

// Expose the necessary types to the rest of the crate.
pub use event::EventRecord;
pub use kernel::{KernelFlag, KernelSession, KernelSessionBuilder};
pub use session::EtwSession;
