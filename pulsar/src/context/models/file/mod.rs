//! Filesystem entity models, format metadata, and access ledger.

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use crate::context::identity::FileKey;

pub mod pe;
pub use pe::{PeExport, PeExportDirectory, PeInfo, PeSection, file_flags, machine, magic, section_flags};

/// Maximum number of file access records retained per file context.
const MAX_ACCESS_HISTORY_ENTRIES: usize = 32;

/// Format-specific structural metadata parsed from file contents.
///
/// Extensible polymorphic container supporting PE executables, and future document formats (Office, PDF).
#[derive(Debug, Clone, Default)]
pub enum FileFormatInfo {
    /// File type is uninspected or unknown format.
    #[default]
    Unknown,
    /// Windows Portable Executable (PE) binary (EXE, DLL, SYS).
    Pe(Arc<PeInfo>),
}

/// Type of file interaction observed by sensors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FileOperationKind {
    Create,
    Open,
    Read,
    Write,
    Delete,
    Rename,
    SetInformation,
    Close,
    Cleanup,
    Flush,
}

/// Record of an individual file access event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileAccessRecord {
    /// The operation performed.
    pub operation: FileOperationKind,
    /// Timestamp of the file operation (FILETIME 100ns ticks).
    pub timestamp: i64,
    /// Number of bytes read or written.
    pub bytes_transferred: u64,
    /// Whether the operation mutated data on disk.
    pub is_write: bool,
}

/// Metadata and state for a tracked filesystem file or directory.
#[derive(Debug)]
pub struct FileContext {
    /// Unique synthetic key for this file entity.
    pub key: FileKey,
    /// Fully normalized absolute filesystem path.
    pub path: String,
    /// Format-specific structural metadata (PE, Office, PDF).
    pub format_info: parking_lot::RwLock<FileFormatInfo>,
    /// Optional SHA-256 hash of the file contents (if calculated).
    pub sha256: parking_lot::RwLock<Option<[u8; 32]>>,
    /// Digital signature verification status / signer name.
    pub signer_name: parking_lot::RwLock<Option<String>>,
    /// Timestamp when this file was first observed by the EDR.
    pub first_seen: i64,
    /// Timestamp of the most recent interaction.
    pub last_accessed: AtomicI64,
    /// Indicates whether any write or mutation operation was observed for this file.
    pub is_modified: AtomicBool,
    /// Bounded ring buffer of recent access operations.
    pub access_history: parking_lot::RwLock<VecDeque<FileAccessRecord>>,
}

impl FileContext {
    /// Instantiates a new tracked file context.
    ///
    /// # Arguments
    ///
    /// * `key` - Monotonically increasing synthetic file identifier.
    /// * `path` - Normalized absolute path string.
    /// * `timestamp` - Discovery timestamp.
    ///
    /// # Returns
    ///
    /// An initialized [`FileContext`].
    pub fn new(key: FileKey, path: String, timestamp: i64) -> Self {
        Self {
            key,
            path,
            format_info: parking_lot::RwLock::new(FileFormatInfo::Unknown),
            sha256: parking_lot::RwLock::new(None),
            signer_name: parking_lot::RwLock::new(None),
            first_seen: timestamp,
            last_accessed: AtomicI64::new(timestamp),
            is_modified: AtomicBool::new(false),
            access_history: parking_lot::RwLock::new(VecDeque::with_capacity(MAX_ACCESS_HISTORY_ENTRIES)),
        }
    }

    /// Sets the format-specific structural metadata for this file entity.
    #[inline]
    pub fn set_format_info(&self, info: FileFormatInfo) {
        *self.format_info.write() = info;
    }

    /// Sets the computed SHA-256 hash for this file entity.
    #[inline]
    pub fn set_sha256(&self, hash: [u8; 32]) {
        *self.sha256.write() = Some(hash);
    }

    /// Returns the computed SHA-256 hash if available.
    #[inline]
    pub fn sha256(&self) -> Option<[u8; 32]> {
        *self.sha256.read()
    }

    /// Sets the digital signature signer name for this file entity.
    #[inline]
    pub fn set_signer_name(&self, name: impl Into<String>) {
        *self.signer_name.write() = Some(name.into());
    }

    /// Returns the digital signature signer name if available.
    #[inline]
    pub fn signer_name(&self) -> Option<String> {
        self.signer_name.read().clone()
    }

    /// Returns the parsed PE metadata if this file is a Portable Executable.
    #[inline]
    pub fn pe_info(&self) -> Option<Arc<PeInfo>> {
        match &*self.format_info.read() {
            FileFormatInfo::Pe(pe) => Some(Arc::clone(pe)),
            _ => None,
        }
    }

    /// Returns `true` if this file is confirmed to be a Portable Executable (PE) binary.
    #[inline]
    pub fn is_pe(&self) -> bool {
        matches!(&*self.format_info.read(), FileFormatInfo::Pe(_))
    }

    /// Returns `true` if this file is confirmed to be an executable or DLL PE image.
    #[inline]
    pub fn is_executable(&self) -> bool {
        if let FileFormatInfo::Pe(pe) = &*self.format_info.read() {
            pe.is_executable_image() || pe.is_dll()
        } else {
            let lower = self.path.to_ascii_lowercase();
            lower.ends_with(".exe") || lower.ends_with(".dll") || lower.ends_with(".sys") || lower.ends_with(".scr")
        }
    }

    /// Records an access event in the bounded access ledger.
    pub fn record_access(&self, record: FileAccessRecord) {
        if record.is_write {
            self.is_modified.store(true, Ordering::Relaxed);
        }
        self.last_accessed.store(record.timestamp, Ordering::Relaxed);

        let mut history = self.access_history.write();
        if history.len() >= MAX_ACCESS_HISTORY_ENTRIES {
            history.pop_front();
        }
        history.push_back(record);
    }

    /// Returns a copy of recent access records.
    pub fn access_history(&self) -> Vec<FileAccessRecord> {
        self.access_history.read().iter().cloned().collect()
    }

    /// Returns `true` if this file has been written to.
    #[inline]
    pub fn has_writes(&self) -> bool {
        self.is_modified.load(Ordering::Relaxed)
    }

    /// Updates the `last_accessed` timestamp.
    #[inline]
    pub fn touch(&self, timestamp: i64) {
        self.last_accessed.fetch_max(timestamp, Ordering::Relaxed);
    }
}
