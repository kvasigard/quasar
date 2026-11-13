//! Per-process Thread representation (`_ETHREAD`).
//!
//! In the Windows Kernel, every thread is represented by an Executive Thread (`_ETHREAD`)
//! structure registered in its owning `_EPROCESS.ThreadListHead`. When a thread is created via
//! `NtCreateThreadEx` or `CreateRemoteThread`, the kernel records:
//! - Which process and thread issued the creation syscall (in the ETW event header's `ProcessId`).
//! - Which target process owns the new thread (in the ETW payload's `ProcessId` / `TThreadId`).
//! - The user-mode entry point (`Win32StartAddr`) where execution begins after `LdrInitializeThunk`.
//!
//! [`ThreadNode`] models this kernel object inside a [`ProcessNode`](crate::model::entities::ProcessNode)
//! to power two high-signal correlation state machines:
//!
//! 1. **Classic DLL Injection (`CreateRemoteThread` -> `LoadLibrary*` / `LdrLoadDll` -> `ImageLoad`)**:
//!    When a remote thread starts at a loader export (e.g. `kernel32!LoadLibraryW`), the target
//!    DLL path is passed in virtual memory (`rcx`), which ETW `ThreadStart` does not capture.
//!    Instead, [`ThreadNode::set_pending_loader_export`] records the matched [`TrackedExport`] on the
//!    `ThreadNode`. When the OS loader maps the DLL on that exact `ThreadId` moments later, the
//!    subsequent `ImageLoad` event consumes the pending export via
//!    [`ThreadNode::take_pending_loader_export`] to link the remote injector, the loader API, and
//!    the loaded `BinaryImage`.
//!
//! 2. **Remote Shellcode Execution (`TiAllocVM` / `TiProtectVM` + `ThreadStart` in Unbacked/W->X VAD)**:
//!    Tracks whether a remote thread's `start_address` targets unbacked or `W -> X` memory, and
//!    latches `alerted_shellcode` via [`ThreadNode::mark_shellcode_alerted`] so delayed enrichment
//!    or repeated checks never emit duplicate alerts for the same thread.

use crate::enrichment::pe::TrackedExport;
use crate::model::entities::process::ProcessKey;
use crate::model::types::{ProcessId, ThreadId};

/// Represents an active thread (`_ETHREAD`) executing inside a process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreadNode {
    /// OS-assigned Thread Identifier (`TThreadId`).
    thread_id: ThreadId,
    /// Process ID of the actor that created this thread (from the ETW event header).
    creator_pid: ProcessId,
    /// Composite [`ProcessKey`] of the creator process if resolved in `ProcessTree` at creation time.
    ///
    /// Preserves attribution against PID reuse if the injector process exits before the
    /// remote thread finishes loading its payload.
    creator_key: Option<ProcessKey>,
    /// `true` when `creator_pid != target_pid` (excluding the initial main thread created during
    /// `NtCreateUserProcess` before the child process has begun executing).
    is_remote: bool,
    /// User-mode entry address (`Win32StartAddr`) where thread execution begins.
    start_address: u64,
    /// High-resolution QPC timestamp when the `ThreadStart` event was recorded.
    created_at_qpc: i64,
    /// Armed when a remote thread's `start_address` matches a tracked loader export
    /// (`LoadLibraryA/W`, `LoadLibraryExA/W`, or `LdrLoadDll`), and consumed (`.take()`)
    /// when the first non-system `ImageLoad` fires on this `thread_id`.
    pending_loader_export: Option<TrackedExport>,
    /// Monotonic latch set to `true` once a remote shellcode / unbacked thread start alert
    /// has been emitted for this thread, preventing duplicate alerts.
    alerted_shellcode: bool,
}

impl ThreadNode {
    /// Constructs a new [`ThreadNode`] with `pending_loader_export = None` and
    /// `alerted_shellcode = false`.
    ///
    /// # Arguments
    ///
    /// * `thread_id` - OS-assigned Thread Identifier (`TThreadId`).
    /// * `creator_pid` - Process ID of the actor that created the thread.
    /// * `creator_key` - Resolved [`ProcessKey`] of the creator process, if known.
    /// * `is_remote` - `true` if created across a process boundary (`creator_pid != target_pid`).
    /// * `start_address` - User-mode entry address (`Win32StartAddr`).
    /// * `created_at_qpc` - High-resolution QPC timestamp of the `ThreadStart` event.
    ///
    /// # Return values
    ///
    /// Returns a newly initialized [`ThreadNode`] in its default unarmed state.
    pub const fn new(
        thread_id: ThreadId,
        creator_pid: ProcessId,
        creator_key: Option<ProcessKey>,
        is_remote: bool,
        start_address: u64,
        created_at_qpc: i64,
    ) -> Self {
        ThreadNode {
            thread_id,
            creator_pid,
            creator_key,
            is_remote,
            start_address,
            created_at_qpc,
            pending_loader_export: None,
            alerted_shellcode: false,
        }
    }

    /// Returns the OS-assigned [`ThreadId`] (`TThreadId`).
    #[inline]
    pub const fn thread_id(&self) -> ThreadId {
        self.thread_id
    }

    /// Returns the [`ProcessId`] of the process that created this thread.
    #[inline]
    pub const fn creator_pid(&self) -> ProcessId {
        self.creator_pid
    }

    /// Returns the composite [`ProcessKey`] of the creator process if it was resolved at creation time.
    #[inline]
    pub const fn creator_key(&self) -> Option<ProcessKey> {
        self.creator_key
    }

    /// Returns `true` if this thread was created remotely by another process (`creator_pid != target_pid`).
    #[inline]
    pub const fn is_remote(&self) -> bool {
        self.is_remote
    }

    /// Returns the user-mode virtual start address (`Win32StartAddr`) of this thread.
    #[inline]
    pub const fn start_address(&self) -> u64 {
        self.start_address
    }

    /// Returns the high-resolution QPC timestamp when this thread was created.
    #[inline]
    pub const fn created_at_qpc(&self) -> i64 {
        self.created_at_qpc
    }

    /// Peeks at the currently armed [`TrackedExport`] without consuming it.
    ///
    /// # Return values
    ///
    /// Returns `Some(TrackedExport)` if this thread is currently armed for a loader-based DLL
    /// injection correlation, or `None` otherwise.
    #[inline]
    pub const fn pending_loader_export(&self) -> Option<TrackedExport> {
        self.pending_loader_export
    }

    /// Arms this thread with a matched [`TrackedExport`] when its `start_address` resolves to
    /// a loader function (`LoadLibrary*` or `LdrLoadDll`).
    ///
    /// # Arguments
    ///
    /// * `export` - The [`TrackedExport`] matched at the thread's `start_address`.
    #[inline]
    pub fn set_pending_loader_export(&mut self, export: TrackedExport) {
        self.pending_loader_export = Some(export);
    }

    /// Consumes and returns the armed [`TrackedExport`] (if any), resetting
    /// `self.pending_loader_export` back to `None`.
    ///
    /// # Why Consume on Read?
    ///
    /// When `LoadLibraryW("evil.dll")` runs inside a remote thread, `evil.dll` itself may have
    /// static imports (e.g. `ws2_32.dll`, `crypt32.dll`) that the Windows loader maps
    /// recursively on the *same* `ThreadId`. Consuming `pending_loader_export` via `.take()` on
    /// the primary payload's `ImageLoad` ensures dependent DLL imports do not trigger false
    /// duplicate injection alerts.
    ///
    /// # Return values
    ///
    /// Returns `Some(TrackedExport)` if a loader export was armed prior to this call, or `None`
    /// if no export was pending (or if it was already consumed by an earlier `ImageLoad`).
    #[inline]
    pub fn take_pending_loader_export(&mut self) -> Option<TrackedExport> {
        self.pending_loader_export.take()
    }

    /// Returns `true` if a shellcode / unbacked start address alert has already been emitted
    /// for this thread.
    #[inline]
    pub const fn is_shellcode_alerted(&self) -> bool {
        self.alerted_shellcode
    }

    /// Permanently latches `alerted_shellcode = true` after a shellcode / unbacked thread start
    /// alert is emitted for this thread.
    ///
    /// Once latched, [`Self::is_shellcode_alerted`] will always return `true` so subsequent
    /// checks never emit duplicate alerts for the same thread.
    #[inline]
    pub fn mark_shellcode_alerted(&mut self) {
        self.alerted_shellcode = true;
    }
}

// ============================================================================
// Unit Test Suite
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_thread_node_initialization() {
        let creator_key = ProcessKey::new(ProcessId(4444), 100_000);
        let thread = ThreadNode::new(
            ThreadId(9001),
            ProcessId(4444),
            Some(creator_key),
            true,
            0x7FFB_1234_5678,
            500_000,
        );

        assert_eq!(thread.thread_id(), ThreadId(9001));
        assert_eq!(thread.creator_pid(), ProcessId(4444));
        assert_eq!(thread.creator_key(), Some(creator_key));
        assert!(thread.is_remote());
        assert_eq!(thread.start_address(), 0x7FFB_1234_5678);
        assert_eq!(thread.created_at_qpc(), 500_000);
        assert_eq!(thread.pending_loader_export(), None);
        assert!(!thread.is_shellcode_alerted());
    }

    #[test]
    fn test_pending_loader_export_consume_once_semantics() {
        let mut thread = ThreadNode::new(
            ThreadId(1024),
            ProcessId(666),
            None,
            true,
            0x7FFB_0001_F480,
            1_000,
        );

        // Initially unarmed
        assert_eq!(thread.take_pending_loader_export(), None);

        // Arm with LoadLibraryW on ThreadStart
        thread.set_pending_loader_export(TrackedExport::LoadLibraryW);
        assert_eq!(
            thread.pending_loader_export(),
            Some(TrackedExport::LoadLibraryW)
        );

        // First ImageLoad on ThreadId(1024) consumes the pending export
        assert_eq!(
            thread.take_pending_loader_export(),
            Some(TrackedExport::LoadLibraryW)
        );

        // Subsequent recursive DLL imports on ThreadId(1024) see None
        assert_eq!(thread.take_pending_loader_export(), None);
        assert_eq!(thread.pending_loader_export(), None);
    }

    #[test]
    fn test_shellcode_alert_latch_idempotency() {
        let mut thread = ThreadNode::new(
            ThreadId(2048),
            ProcessId(666),
            None,
            true,
            0x0000_0200_5000_0000,
            2_000,
        );

        assert!(!thread.is_shellcode_alerted());

        // Latch alert state
        thread.mark_shellcode_alerted();
        assert!(thread.is_shellcode_alerted());

        // Calling mark_shellcode_alerted again keeps the latch true
        thread.mark_shellcode_alerted();
        assert!(thread.is_shellcode_alerted());
    }
}
