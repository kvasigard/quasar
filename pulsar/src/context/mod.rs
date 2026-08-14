//! System-wide execution context, process relationships, and lifecycle tracking.

pub mod handlers;
pub mod process;
pub mod system_tree;

use std::sync::LazyLock;

// Re-export common types for ergonomics across sink implementations
pub use handlers::*;
pub use process::{LoadedModule, ProcessContext, ProcessKey};
pub use system_tree::SystemTree;

/// Global singleton instance of the `SystemTree`.
pub static TREE: LazyLock<SystemTree> = LazyLock::new(SystemTree::new);
