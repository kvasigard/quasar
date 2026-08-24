//! Handle object and access mask model.

use std::sync::Arc;
use crate::context::identity::{FileKey, ProcessKey, ThreadKey};

/// Type of kernel object targeted by a handle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandleTarget {
    /// Process object handle.
    Process(ProcessKey),
    /// Thread object handle.
    Thread(ThreadKey),
    /// Filesystem file object handle.
    File(FileKey),
    /// Registry key path handle.
    Key(Arc<str>),
    /// Section / file mapping handle.
    Section(Arc<str>),
    /// Security token handle.
    Token,
    /// Named mutant / mutex handle.
    Mutant(Arc<str>),
    /// Win32 event synchronization handle.
    Event(Arc<str>),
    /// Other unclassified object type.
    Other(Arc<str>),
}

impl HandleTarget {
    /// Creates a registry key handle target from a string or slice.
    #[inline]
    pub fn key(path: impl Into<Arc<str>>) -> Self {
        Self::Key(path.into())
    }

    /// Creates a section/mapping handle target.
    #[inline]
    pub fn section(name: impl Into<Arc<str>>) -> Self {
        Self::Section(name.into())
    }

    /// Creates a mutant/mutex handle target.
    #[inline]
    pub fn mutant(name: impl Into<Arc<str>>) -> Self {
        Self::Mutant(name.into())
    }

    /// Creates an event handle target.
    #[inline]
    pub fn event(name: impl Into<Arc<str>>) -> Self {
        Self::Event(name.into())
    }

    /// Creates an other unclassified handle target.
    #[inline]
    pub fn other(name: impl Into<Arc<str>>) -> Self {
        Self::Other(name.into())
    }
}

/// Information representing an open kernel handle in a process address space.
#[derive(Debug, Clone)]
pub struct HandleObject {
    /// Raw numeric value of the handle within the process handle table (e.g. 0x04, 0x1c).
    pub handle_value: u64,
    /// What entity/object this handle points to.
    pub target: HandleTarget,
    /// Win32 / NT access mask granted upon opening (e.g. `PROCESS_ALL_ACCESS`, `GENERIC_READ`).
    pub granted_access: u32,
    /// Timestamp when the handle was created / duplicated.
    pub open_time: i64,
}

impl HandleObject {
    // Standard Windows process access rights (WinNT.h)
    #[allow(dead_code)]
    const PROCESS_TERMINATE: u32 = 0x0001;
    const PROCESS_CREATE_THREAD: u32 = 0x0002;
    const PROCESS_VM_OPERATION: u32 = 0x0008;
    const PROCESS_VM_READ: u32 = 0x0010;
    const PROCESS_VM_WRITE: u32 = 0x0020;
    const PROCESS_DUP_HANDLE: u32 = 0x0040;
    #[allow(dead_code)]
    const PROCESS_SUSPEND_RESUME: u32 = 0x0800;

    // Standard Windows thread access rights (WinNT.h)
    const THREAD_SUSPEND_RESUME: u32 = 0x0002;
    const THREAD_SET_CONTEXT: u32 = 0x0010;
    const THREAD_DIRECT_IMPERSONATION: u32 = 0x0200;

    /// Checks if this handle grants write / memory modification permissions to a target process.
    ///
    /// # Returns
    ///
    /// `true` if the access mask includes `PROCESS_VM_WRITE` or `PROCESS_VM_OPERATION`.
    #[inline]
    pub fn has_process_write_access(&self) -> bool {
        (self.granted_access & (Self::PROCESS_VM_WRITE | Self::PROCESS_VM_OPERATION)) != 0
    }

    /// Checks if this handle grants permissions commonly used for process injection
    /// (e.g. VirtualAllocEx/WriteProcessMemory + CreateRemoteThread or DuplicateHandle).
    #[inline]
    pub fn has_process_inject_access(&self) -> bool {
        let inject_mask = Self::PROCESS_VM_WRITE
            | Self::PROCESS_VM_OPERATION
            | Self::PROCESS_CREATE_THREAD
            | Self::PROCESS_DUP_HANDLE;
        (self.granted_access & inject_mask) != 0
    }

    /// Checks if this handle grants read access to remote virtual memory (`PROCESS_VM_READ`).
    #[inline]
    pub fn has_process_read_access(&self) -> bool {
        (self.granted_access & Self::PROCESS_VM_READ) != 0
    }

    /// Checks if this handle grants thread context manipulation or suspension permissions.
    #[inline]
    pub fn has_thread_hijack_access(&self) -> bool {
        let hijack_mask = Self::THREAD_SET_CONTEXT
            | Self::THREAD_SUSPEND_RESUME
            | Self::THREAD_DIRECT_IMPERSONATION;
        (self.granted_access & hijack_mask) != 0
    }

    /// Returns the target `ProcessKey` if this handle targets a process.
    #[inline]
    pub fn target_process(&self) -> Option<ProcessKey> {
        match self.target {
            HandleTarget::Process(k) => Some(k),
            _ => None,
        }
    }

    /// Returns the target `FileKey` if this handle targets a file.
    #[inline]
    pub fn target_file(&self) -> Option<FileKey> {
        match self.target {
            HandleTarget::File(k) => Some(k),
            _ => None,
        }
    }

    /// Returns the target `ThreadKey` if this handle targets a thread.
    #[inline]
    pub fn target_thread(&self) -> Option<ThreadKey> {
        match self.target {
            HandleTarget::Thread(k) => Some(k),
            _ => None,
        }
    }
}
