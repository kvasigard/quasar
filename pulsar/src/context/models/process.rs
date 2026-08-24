//! Process entity models, interior mutability state, and loaded module tracking.

use parking_lot::RwLock;
use std::{
    collections::{HashMap, HashSet},
    sync::atomic::{AtomicBool, AtomicI64, AtomicU32, Ordering},
};
use windows_sys::Win32::Foundation::STILL_ACTIVE;

use crate::context::models::handle::HandleObject;
use crate::context::models::token::TokenContext;
use crate::context::{
    identity::{ConnectionKey, FileKey, ProcessKey},
    module::LoadedModule,
};

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
    pub image_file_name: RwLock<String>,
    /// Full normalized filesystem image path.
    pub image_path: RwLock<Option<String>>,
    /// Full command line invocation string.
    pub command_line: RwLock<Option<String>>,
    /// Package full name for UWP / AppX applications.
    pub package_full_name: RwLock<Option<String>>,
    /// Application ID string.
    pub application_id: RwLock<Option<String>>,

    // --- In-Place Mutable Sub-Tables (Fine-grained Interior Mutability) ---
    /// Security token context.
    pub token: RwLock<TokenContext>,
    /// Dynamic libraries mapped in virtual memory..
    pub loaded_modules: RwLock<Vec<LoadedModule>>,
    /// Active and observed kernel handles
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
            is_pinned: AtomicBool::new(false),
            is_tombstone: AtomicBool::new(false),
            unique_process_key: 0,
            page_directory_base: 0,
            image_file_name: RwLock::new(String::new()),
            image_path: RwLock::new(None),
            command_line: RwLock::new(None),
            package_full_name: RwLock::new(None),
            application_id: RwLock::new(None),
            token: RwLock::new(TokenContext::default()),
            loaded_modules: RwLock::new(Vec::new()),
            handles: RwLock::new(HashMap::new()),
            threads: RwLock::new(HashSet::new()),
            touched_files: RwLock::new(HashSet::new()),
            network_connections: RwLock::new(Vec::new()),
        }
    }

    /// Resolves the [`LoadedModule`] whose mapped virtual address range contains `addr`.
    ///
    /// Performs an $O(\log n)$ lookup via binary search over the sorted module list.
    ///
    /// # Arguments
    ///
    /// * `addr` - The virtual memory address to resolve.
    ///
    /// # Returns
    ///
    /// An [`Option<LoadedModule>`] containing a clone of the matching module metadata,
    /// or [`None`] if the address falls outside all mapped module ranges.
    pub fn find_module_by_address(&self, addr: u64) -> Option<LoadedModule> {
        let modules = self.loaded_modules.read();

        // Binary search identifies either the exact base address match or the insertion index
        // immediately following the preceding module candidate.
        let candidate_idx = match modules.binary_search_by_key(&addr, |m| m.base_address) {
            Ok(exact_idx) => exact_idx,
            Err(idx) => idx.checked_sub(1)?,
        };

        modules
            .get(candidate_idx)
            .filter(|module| module.contains_address(addr))
            .cloned()
    }

    /// Checks whether the process is currently running.
    ///
    /// # Returns
    ///
    /// `true` if the process is alive, `false` if terminated.
    #[inline]
    pub fn is_alive(&self) -> bool {
        self.exit_time.load(Ordering::Relaxed) == 0
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

    /// Explicitly updates the process image file name.
    #[inline]
    pub fn set_image_name(&self, name: impl Into<String>) {
        *self.image_file_name.write() = name.into();
    }

    /// Explicitly updates the full process image path.
    #[inline]
    pub fn set_image_path(&self, path: impl Into<String>) {
        *self.image_path.write() = Some(path.into());
    }

    /// Returns the command line invocation string if recorded.
    #[inline]
    pub fn command_line(&self) -> Option<String> {
        self.command_line.read().clone()
    }

    /// Explicitly updates the process command line invocation string.
    #[inline]
    pub fn set_command_line(&self, cmd: impl Into<String>) {
        *self.command_line.write() = Some(cmd.into());
    }

    /// Returns the package full name for UWP / AppX applications if recorded.
    #[inline]
    pub fn package_full_name(&self) -> Option<String> {
        self.package_full_name.read().clone()
    }

    /// Explicitly updates the package full name for UWP / AppX applications.
    #[inline]
    pub fn set_package_full_name(&self, pkg: impl Into<String>) {
        *self.package_full_name.write() = Some(pkg.into());
    }

    /// Returns the application ID string if recorded.
    #[inline]
    pub fn application_id(&self) -> Option<String> {
        self.application_id.read().clone()
    }

    /// Explicitly updates the application ID string.
    #[inline]
    pub fn set_application_id(&self, app_id: impl Into<String>) {
        *self.application_id.write() = Some(app_id.into());
    }

    /// Records a newly mapped DLL or binary image into this process context in-place.
    ///
    /// If the loaded module is an executable (`.exe`) and the process currently has an empty
    /// image name, automatically populates the process's image name and path.
    ///
    /// Maintains the internal [`Vec<LoadedModule>`] in ascending order by base address.
    /// If a module already exists at `module.base_address`, its metadata is overwritten;
    /// otherwise, it is inserted at the sorted position in $O(n)$ time.
    ///
    /// # Arguments
    ///
    /// * `module` - The loaded module metadata to record.
    pub fn record_module_load(&self, module: LoadedModule) {
        let image_name = module.image_name();
        if image_name.to_ascii_lowercase().ends_with(".exe") {
            let mut name_guard = self.image_file_name.write();
            if name_guard.is_empty() {
                let short_name = image_name
                    .rsplit(&['/', '\\'][..])
                    .next()
                    .unwrap_or(image_name);
                *name_guard = short_name.to_string();
            }
            let mut path_guard = self.image_path.write();
            if path_guard.is_none() {
                *path_guard = Some(image_name.to_string());
            }
        }

        let mut modules = self.loaded_modules.write();
        match modules.binary_search_by_key(&module.base_address, |m| m.base_address) {
            Ok(idx) => modules[idx] = module,
            Err(insert_idx) => modules.insert(insert_idx, module),
        }
    }

    /// Unmaps a module when an image unload event occurs in-place.
    ///
    /// Locates the module by its base address in $O(\log n)$ time using binary search
    /// and shifts subsequent elements to maintain continuous sorted storage.
    ///
    /// # Arguments
    ///
    /// * `base_address` - The virtual base address of the unmapped image.
    ///
    /// # Returns
    ///
    /// An [`Option<LoadedModule>`] containing the removed module metadata, or [`None`]
    /// if no module was mapped at `base_address`.
    pub fn record_module_unload(&self, base_address: u64) -> Option<LoadedModule> {
        let mut modules = self.loaded_modules.write();
        match modules.binary_search_by_key(&base_address, |m| m.base_address) {
            Ok(idx) => Some(modules.remove(idx)),
            Err(_) => {
                log::debug!(
                    "Attempted to unload unmapped module at address {:#x}",
                    base_address
                );
                None
            }
        }
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
        self.exit_status.store(exit_status, Ordering::Release);
        self.exit_time.store(timestamp, Ordering::Release);
    }
}
