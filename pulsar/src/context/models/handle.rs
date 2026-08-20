//! Handle object and access mask model.

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
    Key(String),
    /// Section / file mapping handle.
    Section(String),
    /// Security token handle.
    Token,
    /// Named mutant / mutex handle.
    Mutant(String),
    /// Win32 event synchronization handle.
    Event(String),
    /// Other unclassified object type.
    Other(String),
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
    /// Checks if this handle grants write / memory modification permissions to a target process.
    ///
    /// # Returns
    ///
    /// `true` if the access mask includes `PROCESS_VM_WRITE`, `PROCESS_VM_OPERATION`, or `PROCESS_ALL_ACCESS`.
    pub fn has_process_write_access(&self) -> bool {
        const PROCESS_VM_WRITE: u32 = 0x0020;
        const PROCESS_VM_OPERATION: u32 = 0x0008;
        const PROCESS_ALL_ACCESS: u32 = 0x1FFFFF;

        (self.granted_access & (PROCESS_VM_WRITE | PROCESS_VM_OPERATION)) != 0
            || (self.granted_access & PROCESS_ALL_ACCESS) == PROCESS_ALL_ACCESS
    }
}
