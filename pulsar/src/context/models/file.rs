//! File entity, operations, and access history model.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use crate::context::identity::FileKey;

/// Maximum number of file access records retained per file context.
const MAX_ACCESS_HISTORY_ENTRIES: usize = 32;

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
            sha256: parking_lot::RwLock::new(None),
            signer_name: parking_lot::RwLock::new(None),
            first_seen: timestamp,
            last_accessed: AtomicI64::new(timestamp),
            is_modified: AtomicBool::new(false),
            access_history: parking_lot::RwLock::new(VecDeque::with_capacity(MAX_ACCESS_HISTORY_ENTRIES)),
        }
    }

    /// Records an access event, updating the last accessed timestamp and appending to bounded access history.
    ///
    /// # Arguments
    ///
    /// * `record` - The file access record to append.
    pub fn record_access(&self, record: FileAccessRecord) {
        self.last_accessed.fetch_max(record.timestamp, Ordering::Relaxed);
        if record.is_write {
            self.is_modified.store(true, Ordering::Relaxed);
        }

        let mut history = self.access_history.write();
        if history.len() >= MAX_ACCESS_HISTORY_ENTRIES {
            history.pop_front();
        }
        history.push_back(record);
    }

    /// Records an access event, updating the last accessed timestamp.
    ///
    /// # Arguments
    ///
    /// * `timestamp` - Access timestamp in FILETIME format.
    pub fn touch(&self, timestamp: i64) {
        self.last_accessed.fetch_max(timestamp, Ordering::Relaxed);
    }

    /// Returns a snapshot of recent file access records.
    ///
    /// # Returns
    ///
    /// A vector of [`FileAccessRecord`] items.
    pub fn access_history(&self) -> Vec<FileAccessRecord> {
        self.access_history.read().iter().cloned().collect()
    }

    /// Checks whether any write or modification operations were observed on this file.
    ///
    /// # Returns
    ///
    /// `true` if writes have occurred.
    pub fn has_writes(&self) -> bool {
        self.is_modified.load(Ordering::Relaxed)
    }

    /// Sets the cached SHA-256 hash.
    ///
    /// # Arguments
    ///
    /// * `hash` - 32-byte SHA-256 digest array.
    pub fn set_sha256(&self, hash: [u8; 32]) {
        *self.sha256.write() = Some(hash);
    }

    /// Returns the cached SHA-256 hash if present.
    ///
    /// # Returns
    ///
    /// `Some([u8; 32])` containing the hash if computed, otherwise `None`.
    pub fn sha256(&self) -> Option<[u8; 32]> {
        *self.sha256.read()
    }

    /// Returns the cached signer name if present.
    ///
    /// # Returns
    ///
    /// `Some(String)` containing the signature subject name, or `None`.
    pub fn signer_name(&self) -> Option<String> {
        self.signer_name.read().clone()
    }

    /// Sets the digital signature signer name.
    ///
    /// # Arguments
    ///
    /// * `name` - The signer subject name.
    pub fn set_signer_name(&self, name: impl Into<String>) {
        *self.signer_name.write() = Some(name.into());
    }
}
