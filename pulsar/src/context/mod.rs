//! System-wide execution context, process relationships, and lifecycle tracking.
//!
//! The `SystemContext` engine maintains the real-time knowledge graph of the operating system:
//! - Processes, parent-child topologies, loaded DLLs, open handles, and security tokens.
//! - Normalized filesystem file entities and access operations.
//! - Network sockets and connections mapped to originating processes.
//! - Cross-process interactions (Code Injections, Handle Duplications, Memory Tampering).
//! - Dual-trigger Garbage Collection (Time-bounded TTL + Capacity limits) with Ancestry Tombstones.
//!
//! # Accessing System Context
//!
//! The context engine is exposed via a global singleton accessible from anywhere in the codebase:
//! ```ignore
//! use crate::context::system_context;
//!
//! let ctx = system_context();
//! if let Some(proc) = ctx.process(target_pid) {
//!     for ancestor in proc.ancestors() {
//!         println!("Ancestor: {}", ancestor.image_name());
//!     }
//! }
//! ```

pub mod config;
pub mod correlation;
pub mod enrichment;
pub mod handlers;
pub mod identity;
pub mod models;
pub mod query;
pub mod registries;
pub mod retention;
pub mod system;

#[cfg(test)]
mod tests;

use std::sync::LazyLock;

// Re-export common types for ergonomics across sink implementations and detection rules
pub use config::ContextConfig;
pub use correlation::{InFlightInjection, InjectionCorrelator};
pub use handlers::{
    handle_file_create, handle_file_name, handle_file_operation, handle_file_read_write,
    handle_file_write, handle_image_load, handle_image_unload, handle_process_exit,
    handle_process_start,
};
pub use identity::{ConnectionKey, EntityId, FileKey, InteractionId, ProcessKey, ThreadKey};
pub use models::*;
pub use query::{AncestorIterator, InteractionQuery, ProcessRef};
pub use registries::{FileRegistry, InteractionRegistry, NetworkRegistry, ProcessTree};
pub use retention::RetentionManager;
pub use system::SystemContext;

/// Global `SystemContext` singleton instance.
pub static CONTEXT: LazyLock<SystemContext> = LazyLock::new(SystemContext::new);

/// Returns a reference to the global `SystemContext` singleton.
///
/// # Returns
///
/// A static reference to the shared [`SystemContext`].
#[inline]
pub fn system_context() -> &'static SystemContext {
    &CONTEXT
}
