//! Process model definitions and execution state primitives.
//!
//! Separating the entity model from the container decouples the individual process
//! lifecycle from the system-wide storage, locking, and traversal logic.

use std::{
    collections::HashSet,
    sync::{
        atomic::{AtomicBool, AtomicI64, AtomicU32, AtomicU64, Ordering},
        RwLock,
    },
};
use windows_sys::Win32::Foundation::STILL_ACTIVE;

/// Monotonically increasing synthetic identifier for process lifecycles.
///
/// Windows recycles PIDs rapidly (e.g. PID 4500 dies and is reassigned milliseconds later).
/// Relying on raw PIDs creates historical lookups with race conditions. `ProcessKey` guarantees
/// a globally unique 64-bit ID for each distinct execution lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProcessKey(pub u64);

impl ProcessKey {
    /// Generates a new, thread-safe, monotonically incrementing key.
    ///
    /// # Returns
    ///
    /// A unique `ProcessKey` instance.
    pub fn new() -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(1);
        Self(COUNTER.fetch_add(1, Ordering::Relaxed))
    }
}

impl Default for ProcessKey {
    fn default() -> Self {
        Self::new()
    }
}

/// Metadata representing an executable image or DLL mapped into virtual memory.
#[derive(Debug, Clone)]
pub struct LoadedModule {
    /// Virtual base address where the image was mapped.
    pub base_address: u64,
    /// Size of the mapped image in bytes.
    pub image_size: u64,
    /// Module name or full image path.
    pub image_name: String,
    /// Timestamp when the module was loaded (FILETIME 100ns ticks).
    pub load_time: i64,
    /// Checksum extracted from the PE header.
    pub checksum: u32,
    /// Preferred default base address from the PE header.
    pub default_base: u64,
}

/// Complete execution context for a single process lifecycle instance.
#[derive(Debug)]
pub struct ProcessContext {
    // --- Identification & Topology ---
    /// Unique internal synthetic key.
    pub key: ProcessKey,
    /// Synthetic key of the parent process (if resolved during spawn).
    pub parent_key: Option<ProcessKey>,
    /// Set of direct children spawned by this process instance.
    pub child_keys: RwLock<HashSet<ProcessKey>>,

    // --- Operating System Identifiers ---
    pub pid: u32,
    pub parent_pid: u32,
    pub session_id: u32,

    // --- Execution Lifecycles ---
    /// Process creation timestamp (FILETIME 100ns ticks).
    pub create_time: i64,
    /// Process exit timestamp (0 if currently alive).
    pub exit_time: AtomicI64,
    /// Final NTSTATUS / Win32 exit code (STILL_ACTIVE while running).
    pub exit_status: AtomicU32,
    /// Fast lock-free execution status flag.
    pub is_alive: AtomicBool,

    // --- Kernel Tracing Attributes ---
    /// Address of the kernel `EPROCESS` block from ETW.
    pub unique_process_key: u64,
    /// CR3 Directory Table Base address.
    pub page_directory_base: u64,

    // --- Executable & Invocation Details ---
    pub image_file_name: String,
    pub image_path: Option<String>,
    pub command_line: Option<String>,
    pub package_full_name: Option<String>,
    pub application_id: Option<String>,

    // --- Activity & Memory State ---
    /// List of dynamic libraries currently mapped in this process address space.
    pub loaded_modules: RwLock<Vec<LoadedModule>>,
}

impl ProcessContext {
    /// Instantiates a new process context with default execution state.
    ///
    /// # Arguments
    ///
    /// * `key` - Unique synthetic process identifier.
    /// * `parent_key` - Parent synthetic key if resolved.
    /// * `pid` - Operating system Process ID.
    /// * `parent_pid` - Operating system Parent Process ID.
    /// * `create_time` - Process creation timestamp in FILETIME units.
    ///
    /// # Returns
    ///
    /// An initialized `ProcessContext` marked alive with default fields.
    pub fn new(
        key: ProcessKey,
        parent_key: Option<ProcessKey>,
        pid: u32,
        parent_pid: u32,
        create_time: i64,
    ) -> Self {
        Self {
            key,
            parent_key,
            child_keys: RwLock::new(HashSet::new()),
            pid,
            parent_pid,
            session_id: 0,
            create_time,
            exit_time: AtomicI64::new(0),
            exit_status: AtomicU32::new(STILL_ACTIVE as u32),
            is_alive: AtomicBool::new(true),
            unique_process_key: 0,
            page_directory_base: 0,
            image_file_name: String::new(),
            image_path: None,
            command_line: None,
            package_full_name: None,
            application_id: None,
            loaded_modules: RwLock::new(Vec::new()),
        }
    }

    /// Records a newly mapped DLL or binary image into this process context.
    ///
    /// # Arguments
    ///
    /// * `module` - The `LoadedModule` metadata to insert.
    pub fn record_module_load(&self, module: LoadedModule) {
        let mut modules = self.loaded_modules.write().unwrap();
        // Prevent duplicates caused by repeated rundown trace passes
        if !modules.iter().any(|m| m.base_address == module.base_address) {
            modules.push(module);
        }
    }

    /// Unmaps a module when an image unload event occurs.
    ///
    /// # Arguments
    ///
    /// * `base_address` - The virtual base address of the unmapped image.
    pub fn record_module_unload(&self, base_address: u64) {
        let mut modules = self.loaded_modules.write().unwrap();
        modules.retain(|m| m.base_address != base_address);
    }

    /// Updates internal state flags and exit code when the process terminates.
    ///
    /// # Arguments
    ///
    /// * `exit_status` - Final Win32/NTSTATUS exit code.
    /// * `timestamp` - Process exit timestamp in FILETIME units.
    pub fn mark_terminated(&self, exit_status: u32, timestamp: i64) {
        self.is_alive.store(false, Ordering::Release);
        self.exit_status.store(exit_status, Ordering::Release);
        self.exit_time.store(timestamp, Ordering::Release);
    }
}
