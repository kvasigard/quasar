//! Fluent file query interface and relational inspection wrappers.

use std::sync::Arc;

use crate::context::SystemContext;
use crate::context::identity::FileKey;
use crate::context::models::file::{FileAccessRecord, FileContext, FileFormatInfo, PeExport, PeInfo};
use crate::context::query::process_query::ProcessRef;

/// Ergonomic, fluent query wrapper around an `Arc<FileContext>` snapshot.
///
/// Provides detection engineers and sinks with a type-safe interface for inspecting
/// file metadata, access history, PE export tables, and accessing/modifying processes.
#[derive(Clone)]
pub struct FileRef<'a> {
    pub(crate) ctx: &'a SystemContext,
    pub(crate) inner: Arc<FileContext>,
}

impl<'a> FileRef<'a> {
    /// Creates a new `FileRef` query handle.
    ///
    /// # Arguments
    ///
    /// * `ctx` - Reference to the root [`SystemContext`].
    /// * `inner` - Shared pointer to the target [`FileContext`].
    pub fn new(ctx: &'a SystemContext, inner: Arc<FileContext>) -> Self {
        Self { ctx, inner }
    }

    /// Access the underlying `FileContext` directly.
    #[inline]
    pub fn context(&self) -> &FileContext {
        &self.inner
    }

    /// Returns the synthetic, monotonically increasing `FileKey`.
    #[inline]
    pub fn key(&self) -> FileKey {
        self.inner.key
    }

    /// Returns the fully normalized absolute file path.
    #[inline]
    pub fn path(&self) -> &str {
        &self.inner.path
    }

    /// Returns the base name / file name component of the path.
    pub fn file_name(&self) -> &str {
        self.inner
            .path
            .rsplit(&['/', '\\'][..])
            .next()
            .unwrap_or(&self.inner.path)
    }

    /// Returns the format-specific structural metadata.
    #[inline]
    pub fn format_info(&self) -> FileFormatInfo {
        self.inner.format_info.read().clone()
    }

    /// Returns the parsed PE metadata if this file is a Portable Executable.
    #[inline]
    pub fn pe_info(&self) -> Option<Arc<PeInfo>> {
        self.inner.pe_info()
    }

    /// Returns `true` if this file is confirmed to be a Portable Executable (PE) binary.
    #[inline]
    pub fn is_pe(&self) -> bool {
        self.inner.is_pe()
    }

    /// Returns `true` if this file is an executable binary or DLL image.
    #[inline]
    pub fn is_executable(&self) -> bool {
        self.inner.is_executable()
    }

    /// Returns `true` if any write or modification operation was observed on this file.
    #[inline]
    pub fn has_writes(&self) -> bool {
        self.inner.has_writes()
    }

    /// Returns `true` if the file has been modified on disk.
    #[inline]
    pub fn is_modified(&self) -> bool {
        self.inner.has_writes()
    }

    /// Returns the SHA-256 hash bytes if computed.
    #[inline]
    pub fn sha256(&self) -> Option<[u8; 32]> {
        *self.inner.sha256.read()
    }

    /// Returns the SHA-256 hash formatted as a hex string.
    pub fn sha256_hex(&self) -> Option<String> {
        self.sha256().map(|bytes| {
            bytes.iter().map(|b| format!("{:02x}", b)).collect()
        })
    }

    /// Returns the digital signature signer name if verified.
    #[inline]
    pub fn signer_name(&self) -> Option<String> {
        self.inner.signer_name.read().clone()
    }

    /// Returns timestamp when this file was first discovered.
    #[inline]
    pub fn first_seen(&self) -> i64 {
        self.inner.first_seen
    }

    /// Returns the timestamp of the most recent access operation.
    #[inline]
    pub fn last_accessed(&self) -> i64 {
        self.inner.last_accessed.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Returns a snapshot copy of recent access operations on this file.
    #[inline]
    pub fn access_history(&self) -> Vec<FileAccessRecord> {
        self.inner.access_history()
    }

    /// Returns all exported symbols if this file is an enriched PE binary.
    pub fn exports(&self) -> Vec<PeExport> {
        self.pe_info()
            .and_then(|pe| pe.exports.as_ref().map(|exp| exp.exports.clone()))
            .unwrap_or_default()
    }

    /// Finds a function's entrypoint RVA by exported name if this file is a PE binary.
    pub fn find_export_rva(&self, name: &str) -> Option<u32> {
        self.pe_info()?.find_export_by_name(name)
    }

    /// Queries all active processes currently tracked in the system that have accessed this file.
    pub fn accessing_processes(&self) -> Vec<ProcessRef<'a>> {
        let target_key = self.inner.key;
        self.ctx
            .processes
            .all_active_pids()
            .into_iter()
            .filter_map(|pid| self.ctx.process(pid))
            .filter(|proc| proc.inner.touched_files.read().contains(&target_key))
            .collect()
    }

    /// Queries all active processes that have performed write/modification operations on this file.
    pub fn modifying_processes(&self) -> Vec<ProcessRef<'a>> {
        let target_key = self.inner.key;
        self.accessing_processes()
            .into_iter()
            .filter(|proc| {
                proc.inner.touched_files.read().contains(&target_key) && self.has_writes()
            })
            .collect()
    }
}
