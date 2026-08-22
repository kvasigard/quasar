//! Filesystem file I/O pipeline domain events.

use crate::context::identity::{FileKey, ProcessKey};
use crate::context::models::file::FileOperationKind;

/// Strongly-typed event representing a filesystem file creation or open.
#[derive(Debug, Clone)]
pub struct FileCreateEvent {
    /// Synthetic key of the originating process.
    pub process_key: ProcessKey,
    /// Operating system Process ID.
    pub pid: u32,
    /// Synthetic key of the created/opened file.
    pub file_key: FileKey,
    /// Kernel FileObject pointer descriptor.
    pub file_object: u64,
    /// Normalized absolute filesystem path.
    pub file_path: String,
    /// Creation disposition and options flags.
    pub create_options: u32,
    /// File attributes mask.
    pub file_attributes: u32,
    /// Shared access permissions mask.
    pub share_access: u32,
    /// Event timestamp (FILETIME 100ns ticks).
    pub timestamp: i64,
}

/// Strongly-typed event representing a filesystem read or write operation.
#[derive(Debug, Clone)]
pub struct FileReadWriteEvent {
    /// Synthetic key of the originating process.
    pub process_key: ProcessKey,
    /// Operating system Process ID.
    pub pid: u32,
    /// Synthetic key of the target file (if resolved from FileObject).
    pub file_key: Option<FileKey>,
    /// Kernel FileObject pointer descriptor.
    pub file_object: u64,
    /// Normalized file path (if resolved).
    pub file_path: Option<String>,
    /// Whether this operation is a write (`true`) or read (`false`).
    pub is_write: bool,
    /// Starting file byte offset.
    pub offset: u64,
    /// Number of bytes transferred.
    pub io_size: u32,
    /// IO request packet flags.
    pub io_flags: u32,
    /// Event timestamp (FILETIME 100ns ticks).
    pub timestamp: i64,
}

/// Strongly-typed event representing a filesystem control or metadata operation (SetInfo, Delete, Rename, Close).
#[derive(Debug, Clone)]
pub struct FileOperationEvent {
    /// Synthetic key of the originating process.
    pub process_key: ProcessKey,
    /// Operating system Process ID.
    pub pid: u32,
    /// Synthetic key of the target file (if resolved from FileObject).
    pub file_key: Option<FileKey>,
    /// Kernel FileObject pointer descriptor.
    pub file_object: u64,
    /// Normalized file path (if resolved).
    pub file_path: Option<String>,
    /// Type of file operation performed.
    pub operation: FileOperationKind,
    /// Extra info (e.g. disposition or allocation size).
    pub extra_info: u64,
    /// Requested file information class.
    pub info_class: u32,
    /// Event timestamp (FILETIME 100ns ticks).
    pub timestamp: i64,
}

/// Aggregates all filesystem telemetry event variants.
#[derive(Debug, Clone)]
pub enum FileIoEvent {
    /// File creation or open event.
    Create(FileCreateEvent),
    /// File read or write event.
    ReadWrite(FileReadWriteEvent),
    /// File metadata or lifecycle operation (delete, rename, setinfo, close, cleanup).
    Operation(FileOperationEvent),
}
