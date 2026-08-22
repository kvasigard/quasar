//! Image mapping and dynamic library pipeline events.

use crate::context::identity::ProcessKey;
use crate::context::models::module::LoadedModule;

/// Strongly-typed event representing a DLL or binary mapped into memory.
#[derive(Debug, Clone)]
pub struct ImageLoadEvent {
    /// Synthetic unique key of the process loading the module.
    pub process_key: ProcessKey,
    /// Operating system Process ID (PID).
    pub pid: u32,
    /// Loaded module metadata.
    pub module: LoadedModule,
    /// Event timestamp (FILETIME 100ns ticks).
    pub timestamp: i64,
}

/// Strongly-typed event representing a DLL or binary unmapped from memory.
#[derive(Debug, Clone)]
pub struct ImageUnloadEvent {
    /// Synthetic unique key of the process unmapping the module.
    pub process_key: ProcessKey,
    /// Operating system Process ID (PID).
    pub pid: u32,
    /// Virtual base address of the unmapped image.
    pub base_address: u64,
    /// Event timestamp (FILETIME 100ns ticks).
    pub timestamp: i64,
}
