//! Process entity models, interior mutability state, and loaded module tracking.

use std::{
    collections::{HashMap, HashSet},
    sync::atomic::{AtomicBool, AtomicI64, AtomicU32, Ordering},
};
use parking_lot::RwLock;
use windows_sys::Win32::Foundation::STILL_ACTIVE;

use crate::context::identity::{ConnectionKey, FileKey, ProcessKey};
use crate::context::models::handle::HandleObject;
use crate::context::models::token::TokenContext;

/// Metadata representing an executable binary or DLL mapped into virtual memory.
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
    /// Whether this module image is unbacked by a physical file on disk (memory-only/reflective DLL).
    pub is_unbacked: bool,
}

/// Complete execution context for a single process lifecycle instance.
///
/// Implements fine-grained in-place interior mutability via `parking_lot::RwLock` and atomics
/// so high-rate telemetry (thousands of handle opens, module loads, file accesses) updates
/// in place without cloning the root context.
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
    /// Operating system Process ID (PID).
    pub pid: u32,
    /// Operating system Parent Process ID (PPID).
    pub parent_pid: u32,
    /// Windows terminal/console session ID.
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

    // --- Retention & Forensics Control ---
    /// When `true`, this process is exempt from garbage collection (e.g. involved in an alert).
    pub is_pinned: AtomicBool,
    /// When `true`, heavy collections have been deallocated, preserving only ancestry skeleton.
    pub is_tombstone: AtomicBool,

    // --- Kernel Tracing Attributes ---
    /// Address of the kernel `EPROCESS` block from ETW.
    pub unique_process_key: u64,
    /// CR3 Directory Table Base address.
    pub page_directory_base: u64,

    // --- Executable & Invocation Details ---
    /// Base image file name (e.g. "cmd.exe").
    pub image_file_name: String,
    /// Full normalized filesystem image path.
    pub image_path: Option<String>,
    /// Full command line invocation string.
    pub command_line: Option<String>,
    /// Package full name for UWP / AppX applications.
    pub package_full_name: Option<String>,
    /// Application ID string.
    pub application_id: Option<String>,

    // --- In-Place Mutable Sub-Tables (Fine-grained Interior Mutability) ---
    /// Security token context.
    pub token: RwLock<TokenContext>,
    /// Dynamic libraries mapped in virtual memory: `BaseAddress -> LoadedModule`.
    pub loaded_modules: RwLock<HashMap<u64, LoadedModule>>,
    /// Active and observed kernel handles: `HandleValue -> HandleObject`.
    pub handles: RwLock<HashMap<u64, HandleObject>>,
    /// Active thread IDs (TIDs) owned by this process.
    pub threads: RwLock<HashSet<u32>>,
    /// Set of filesystem files accessed or modified by this process.
    pub touched_files: RwLock<HashSet<FileKey>>,
    /// Network connections established or accepted by this process.
    pub network_connections: RwLock<Vec<ConnectionKey>>,
}

impl ProcessContext {
    /// Instantiates a new process context with default execution state.
    ///
    /// # Arguments
    ///
    /// * `key` - Monotonically increasing synthetic identifier.
    /// * `parent_key` - Resolved synthetic key of the parent process, if known.
    /// * `pid` - Operating system Process ID.
    /// * `parent_pid` - Operating system Parent Process ID.
    /// * `create_time` - Process creation timestamp in FILETIME format.
    ///
    /// # Returns
    ///
    /// An initialized [`ProcessContext`].
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
            is_pinned: AtomicBool::new(false),
            is_tombstone: AtomicBool::new(false),
            unique_process_key: 0,
            page_directory_base: 0,
            image_file_name: String::new(),
            image_path: None,
            command_line: None,
            package_full_name: None,
            application_id: None,
            token: RwLock::new(TokenContext::default()),
            loaded_modules: RwLock::new(HashMap::new()),
            handles: RwLock::new(HashMap::new()),
            threads: RwLock::new(HashSet::new()),
            touched_files: RwLock::new(HashSet::new()),
            network_connections: RwLock::new(Vec::new()),
        }
    }

    /// Checks whether the process is currently running.
    ///
    /// # Returns
    ///
    /// `true` if the process is alive, `false` if terminated.
    #[inline]
    pub fn is_alive(&self) -> bool {
        self.is_alive.load(Ordering::Relaxed)
    }

    /// Checks if this process is currently pinned for forensic investigation.
    ///
    /// # Returns
    ///
    /// `true` if pinned and exempt from retention eviction.
    #[inline]
    pub fn is_pinned(&self) -> bool {
        self.is_pinned.load(Ordering::Relaxed)
    }

    /// Checks if this process has been converted into a lightweight tombstone.
    ///
    /// # Returns
    ///
    /// `true` if heavy allocations have been stripped to retain only ancestry.
    #[inline]
    pub fn is_tombstone(&self) -> bool {
        self.is_tombstone.load(Ordering::Relaxed)
    }

    /// Pins this process to preserve forensic context and prevent GC eviction.
    #[inline]
    pub fn pin(&self) {
        self.is_pinned.store(true, Ordering::Relaxed);
    }

    /// Unpins this process, allowing normal retention policies to apply.
    #[inline]
    pub fn unpin(&self) {
        self.is_pinned.store(false, Ordering::Relaxed);
    }

    /// Converts this process into a lightweight tombstone by deallocating heavy sub-collections.
    pub fn convert_to_tombstone(&self) {
        self.is_tombstone.store(true, Ordering::Release);
        self.loaded_modules.write().clear();
        self.handles.write().clear();
        self.threads.write().clear();
        self.touched_files.write().clear();
        self.network_connections.write().clear();
    }

    // --- In-Place Mutation Primitives ---

    /// Records a newly mapped DLL or binary image into this process context in-place.
    ///
    /// # Arguments
    ///
    /// * `module` - The loaded module metadata.
    pub fn record_module_load(&self, module: LoadedModule) {
        self.loaded_modules.write().insert(module.base_address, module);
    }

    /// Unmaps a module when an image unload event occurs in-place.
    ///
    /// # Arguments
    ///
    /// * `base_address` - The virtual base address of the unmapped image.
    pub fn record_module_unload(&self, base_address: u64) {
        self.loaded_modules.write().remove(&base_address);
    }

    /// Records an opened kernel handle in-place.
    ///
    /// # Arguments
    ///
    /// * `handle` - The handle metadata object.
    pub fn record_handle_open(&self, handle: HandleObject) {
        self.handles.write().insert(handle.handle_value, handle);
    }

    /// Records a closed kernel handle in-place.
    ///
    /// # Arguments
    ///
    /// * `handle_value` - The numerical handle descriptor value.
    pub fn record_handle_close(&self, handle_value: u64) {
        self.handles.write().remove(&handle_value);
    }

    /// Records a thread ID created inside this process.
    ///
    /// # Arguments
    ///
    /// * `tid` - Operating system Thread ID.
    pub fn record_thread_create(&self, tid: u32) {
        self.threads.write().insert(tid);
    }

    /// Records a thread termination.
    ///
    /// # Arguments
    ///
    /// * `tid` - Operating system Thread ID.
    pub fn record_thread_exit(&self, tid: u32) {
        self.threads.write().remove(&tid);
    }

    /// Records file access by this process.
    ///
    /// # Arguments
    ///
    /// * `file_key` - Synthetic key of the accessed file.
    pub fn record_file_access(&self, file_key: FileKey) {
        self.touched_files.write().insert(file_key);
    }

    /// Records a network socket connection established by this process.
    ///
    /// # Arguments
    ///
    /// * `conn_key` - Synthetic key of the connection.
    pub fn record_network_connection(&self, conn_key: ConnectionKey) {
        self.network_connections.write().push(conn_key);
    }

    /// Updates internal state flags and exit code when the process terminates.
    ///
    /// # Arguments
    ///
    /// * `exit_status` - The Win32 / NTSTATUS exit code.
    /// * `timestamp` - Termination timestamp in FILETIME format.
    pub fn mark_terminated(&self, exit_status: u32, timestamp: i64) {
        self.is_alive.store(false, Ordering::Release);
        self.exit_status.store(exit_status, Ordering::Release);
        self.exit_time.store(timestamp, Ordering::Release);
    }
}
