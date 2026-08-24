//! Fluent process query interface and graph-traversal iterators.

use std::sync::Arc;

use crate::context::SystemContext;
use crate::context::identity::{FileKey, ProcessKey};
use crate::context::models::handle::HandleObject;
use crate::context::models::interaction::InteractionRecord;
use crate::context::models::module::LoadedModule;
use crate::context::models::network::NetworkConnection;
use crate::context::models::process::ProcessContext;
use crate::context::models::token::TokenContext;
use crate::context::query::file_query::FileRef;

/// Ergonomic, fluent query wrapper around an `Arc<ProcessContext>` snapshot.
///
/// Designed to provide detection engineers with a type-safe, expressive API
/// for querying process topology, ancestry chains, handles, modules, and cross-process interactions.
#[derive(Clone)]
pub struct ProcessRef<'a> {
    pub(crate) ctx: &'a SystemContext,
    pub(crate) inner: Arc<ProcessContext>,
}

impl<'a> ProcessRef<'a> {
    /// Creates a new `ProcessRef` query handle.
    ///
    /// # Arguments
    ///
    /// * `ctx` - Reference to the root [`SystemContext`].
    /// * `inner` - Shared pointer to the target [`ProcessContext`].
    ///
    /// # Returns
    ///
    /// A new [`ProcessRef`] query wrapper.
    pub fn new(ctx: &'a SystemContext, inner: Arc<ProcessContext>) -> Self {
        Self { ctx, inner }
    }

    /// Access the underlying `ProcessContext` directly for in-place mutation or low-level inspection.
    ///
    /// # Returns
    ///
    /// A reference to the wrapped [`ProcessContext`].
    #[inline]
    pub fn context(&self) -> &ProcessContext {
        &self.inner
    }

    /// Returns the synthetic, monotonically increasing `ProcessKey`.
    ///
    /// # Returns
    ///
    /// The unique [`ProcessKey`].
    #[inline]
    pub fn key(&self) -> ProcessKey {
        self.inner.key
    }

    /// Returns the operating system Process ID (PID).
    ///
    /// # Returns
    ///
    /// The OS PID.
    #[inline]
    pub fn pid(&self) -> u32 {
        self.inner.pid
    }

    /// Returns the operating system Parent Process ID (PPID).
    ///
    /// # Returns
    ///
    /// The OS PPID.
    #[inline]
    pub fn parent_pid(&self) -> u32 {
        self.inner.parent_pid
    }

    /// Returns the image file name (e.g., "cmd.exe" or "powershell.exe").
    ///
    /// # Returns
    ///
    /// The image file name.
    #[inline]
    pub fn image_file_name(&self) -> String {
        self.inner.image_file_name.read().clone()
    }

    /// Returns the full image path if available.
    ///
    /// # Returns
    ///
    /// `Some(String)` containing the full path, or `None`.
    #[inline]
    pub fn image_path(&self) -> Option<String> {
        self.inner.image_path.read().clone()
    }

    /// Returns the base name of the process image.
    ///
    /// # Returns
    ///
    /// Extracted file name.
    pub fn image_name(&self) -> String {
        let path_guard = self.inner.image_path.read();
        if let Some(path) = path_guard.as_deref() {
            return path.rsplit(&['/', '\\'][..]).next().unwrap_or(path).to_string();
        }
        let name_guard = self.inner.image_file_name.read();
        if !name_guard.is_empty() {
            return name_guard.clone();
        }
        "unknown".to_string()
    }

    /// Returns the process command line invocation string if available.
    ///
    /// # Returns
    ///
    /// `Some(String)` containing the command line, or `None`.
    #[inline]
    pub fn command_line(&self) -> Option<String> {
        self.inner.command_line()
    }

    /// Returns the package full name for UWP / AppX applications if available.
    #[inline]
    pub fn package_full_name(&self) -> Option<String> {
        self.inner.package_full_name()
    }

    /// Returns the application ID string if available.
    #[inline]
    pub fn application_id(&self) -> Option<String> {
        self.inner.application_id()
    }

    /// Checks if the process token is elevated (Administrator or SYSTEM).
    #[inline]
    pub fn is_elevated(&self) -> bool {
        self.inner.token.read().is_elevated
    }

    /// Returns the token integrity level for this process.
    #[inline]
    pub fn integrity(&self) -> crate::context::models::token::IntegrityLevel {
        self.inner.token.read().integrity
    }

    /// Checks if a specific privilege is enabled on the process token.
    #[inline]
    pub fn has_privilege(&self, priv_name: &str) -> bool {
        self.inner.token.read().has_privilege(priv_name)
    }

    /// Returns the process creation timestamp (FILETIME 100ns ticks).
    ///
    /// # Returns
    ///
    /// Creation timestamp integer.
    #[inline]
    pub fn create_time(&self) -> i64 {
        self.inner.create_time
    }

    /// Checks if this process is currently running.
    ///
    /// # Returns
    ///
    /// `true` if active.
    #[inline]
    pub fn is_alive(&self) -> bool {
        self.inner.is_alive()
    }

    /// Checks if this process is pinned for forensic retention.
    ///
    /// # Returns
    ///
    /// `true` if pinned.
    #[inline]
    pub fn is_pinned(&self) -> bool {
        self.inner.is_pinned()
    }

    /// Checks if this process has been converted to an ancestry tombstone.
    ///
    /// # Returns
    ///
    /// `true` if tombstone.
    #[inline]
    pub fn is_tombstone(&self) -> bool {
        self.inner.is_tombstone()
    }

    /// Pins this process, exempting it and its tree from GC eviction during investigations.
    #[inline]
    pub fn pin(&self) {
        self.inner.pin();
    }

    /// Unpins this process.
    #[inline]
    pub fn unpin(&self) {
        self.inner.unpin();
    }

    /// Returns a clone of the process security token context.
    ///
    /// # Returns
    ///
    /// A [`TokenContext`] snapshot.
    pub fn token(&self) -> TokenContext {
        self.inner.token.read().clone()
    }

    /// Resolves the parent process context if it exists in the arena.
    ///
    /// # Returns
    ///
    /// `Some(ProcessRef)` for the parent process, or `None`.
    pub fn parent(&self) -> Option<ProcessRef<'a>> {
        let parent_key = self.inner.parent_key?;
        let parent_proc = self.ctx.processes.get_by_key(parent_key)?;
        Some(ProcessRef::new(self.ctx, parent_proc))
    }

    /// Returns a lazy iterator walking upwards through the process ancestry tree.
    ///
    /// # Returns
    ///
    /// An [`AncestorIterator`] traversing ancestors from immediate parent upwards.
    pub fn ancestors(&self) -> AncestorIterator<'a> {
        AncestorIterator {
            ctx: self.ctx,
            current_key: self.inner.parent_key,
        }
    }

    /// Returns a list of direct child processes spawned by this instance.
    ///
    /// # Returns
    ///
    /// A vector of [`ProcessRef`] handles for active children.
    pub fn children(&self) -> Vec<ProcessRef<'a>> {
        let keys = self.inner.child_keys.read();
        keys.iter()
            .filter_map(|k| self.ctx.processes.get_by_key(*k))
            .map(|p| ProcessRef::new(self.ctx, p))
            .collect()
    }

    /// Returns a snapshot list of dynamic modules/DLLs loaded in this process.
    ///
    /// # Returns
    ///
    /// A vector of [`LoadedModule`] descriptors.
    pub fn loaded_modules(&self) -> Vec<LoadedModule> {
        self.inner.loaded_modules.read().clone()
    }

    /// Checks if this process has loaded a specific module by name (case-insensitive).
    ///
    /// # Arguments
    ///
    /// * `module_name` - Module name or substring to search.
    ///
    /// # Returns
    ///
    /// `true` if matching module is mapped in virtual memory.
    pub fn has_module(&self, module_name: &str) -> bool {
        let lower = module_name.to_lowercase();
        self.inner
            .loaded_modules
            .read()
            .iter()
            .any(|m| m.image_name().to_lowercase().contains(&lower))
    }

    /// Resolves a virtual memory address to its owning loaded module within this process.
    ///
    /// # Arguments
    ///
    /// * `addr` - The 64-bit virtual memory address to resolve.
    ///
    /// # Returns
    ///
    /// `Some(LoadedModule)` if the address is within mapped module bounds, otherwise `None`.
    #[inline]
    pub fn find_module_by_address(&self, addr: u64) -> Option<LoadedModule> {
        self.inner.find_module_by_address(addr)
    }

    /// Returns a snapshot list of open kernel handles tracked for this process.
    ///
    /// # Returns
    ///
    /// A vector of [`HandleObject`] descriptors.
    pub fn handles(&self) -> Vec<HandleObject> {
        self.inner.handles.read().values().cloned().collect()
    }

    /// Returns all open kernel handles held by this process that target a specific process.
    ///
    /// # Arguments
    ///
    /// * `target_key` - Synthetic process key of the target process.
    pub fn handles_to_process(&self, target_key: ProcessKey) -> Vec<HandleObject> {
        self.inner
            .handles
            .read()
            .values()
            .filter(|h| h.target_process() == Some(target_key))
            .cloned()
            .collect()
    }

    /// Returns all open kernel handles held by this process that target a specific file.
    ///
    /// # Arguments
    ///
    /// * `file_key` - Synthetic file key of the target file.
    pub fn handles_to_file(&self, file_key: FileKey) -> Vec<HandleObject> {
        self.inner
            .handles
            .read()
            .values()
            .filter(|h| h.target_file() == Some(file_key))
            .cloned()
            .collect()
    }

    /// Returns a snapshot of referenced file keys accessed by this process.
    ///
    /// # Returns
    ///
    /// A vector of [`FileKey`] identifiers.
    pub fn touched_file_keys(&self) -> Vec<FileKey> {
        self.inner.touched_files.read().iter().copied().collect()
    }

    /// Returns a snapshot of all [`FileRef`] query handles touched by this process.
    ///
    /// # Returns
    ///
    /// A vector of [`FileRef`] query handles.
    pub fn touched_files(&self) -> Vec<FileRef<'a>> {
        let keys = self.inner.touched_files.read();
        keys.iter()
            .filter_map(|key| {
                self.ctx
                    .files
                    .get_by_key(*key)
                    .map(|inner| FileRef::new(self.ctx, inner))
            })
            .collect()
    }

    /// Returns all files accessed by this process that have observed write operations.
    ///
    /// # Returns
    ///
    /// A vector of [`FileRef`] references with write activity.
    pub fn recent_file_writes(&self) -> Vec<FileRef<'a>> {
        self.touched_files()
            .into_iter()
            .filter(|f| f.has_writes())
            .collect()
    }

    /// Returns all files modified by this process.
    ///
    /// # Returns
    ///
    /// A vector of [`FileRef`] references.
    #[inline]
    pub fn modified_files(&self) -> Vec<FileRef<'a>> {
        self.recent_file_writes()
    }

    /// Returns all network connections initiated or accepted by this process.
    ///
    /// # Returns
    ///
    /// A vector of [`NetworkConnection`] references.
    pub fn network_connections(&self) -> Vec<Arc<NetworkConnection>> {
        self.ctx.network.process_connections(self.inner.key)
    }

    /// Returns all code injection interactions that targeted this process.
    ///
    /// # Returns
    ///
    /// A vector of [`InteractionRecord`] references.
    pub fn inbound_injections(&self) -> Vec<Arc<InteractionRecord>> {
        self.ctx.interactions.injections_into(self.inner.key)
    }

    /// Resolves the [`FileRef`] query handle for the main executable image of this process.
    pub fn main_image_file(&self) -> Option<FileRef<'a>> {
        let name = self.image_name();
        if (name.contains('\\') || name.contains('/'))
            && let Some(f) = self.ctx.file(&name)
        {
            return Some(f);
        }

        // Check loaded modules for matching image binary
        let lower_base = self.image_file_name().to_ascii_lowercase();
        for m in self.loaded_modules() {
            let m_name = m.image_name().to_ascii_lowercase();
            if (m_name.ends_with(&lower_base) || m_name.contains(&lower_base))
                && let Some(key) = m.file_key()
                && let Some(f) = self.ctx.file_by_key(key)
            {
                return Some(f);
            }
        }

        self.touched_files()
            .into_iter()
            .find(|f| f.file_name().eq_ignore_ascii_case(&lower_base))
    }

    /// Returns `true` if the main executable image of this process is verified and signed.
    pub fn is_image_signed(&self) -> bool {
        self.main_image_file()
            .map(|f| f.is_signed())
            .unwrap_or(false)
    }

    /// Returns `true` if the main executable image of this process is signed by Microsoft.
    pub fn is_image_microsoft(&self) -> bool {
        self.main_image_file()
            .map(|f| f.is_microsoft())
            .unwrap_or(false)
    }

    /// Returns all loaded non-system modules whose underlying binary file is confirmed to be unsigned.
    pub fn unsigned_loaded_modules(&self) -> Vec<LoadedModule> {
        self.loaded_modules()
            .into_iter()
            .filter(|m| {
                if m.is_system() {
                    return false;
                }
                if let Some(key) = m.file_key()
                    && let Some(file) = self.ctx.file_by_key(key)
                {
                    return file.is_unsigned();
                }
                false
            })
            .collect()
    }
}

/// Lazy iterator traversing process ancestry upwards `[Parent, Grandparent, ...]`.
pub struct AncestorIterator<'a> {
    ctx: &'a SystemContext,
    current_key: Option<ProcessKey>,
}

impl<'a> Iterator for AncestorIterator<'a> {
    type Item = ProcessRef<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let key = self.current_key?;
        let proc = self.ctx.processes.get_by_key(key)?;
        self.current_key = proc.parent_key;
        Some(ProcessRef::new(self.ctx, proc))
    }
}
