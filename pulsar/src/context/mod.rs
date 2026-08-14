//! System-wide execution context, process relationships, and lifecycle tracking.

pub mod handlers;
pub mod process;
pub mod process_tree;
pub mod system;

use std::sync::LazyLock;

// Re-export common types for ergonomics across sink implementations
pub use crate::error::HandlerError;
pub use handlers::*;
pub use process::{LoadedModule, ProcessContext, ProcessKey};
pub use system::SystemContext;

/// Global singleton
pub static CONTEXT: LazyLock<SystemContext> = LazyLock::new(SystemContext::new);
