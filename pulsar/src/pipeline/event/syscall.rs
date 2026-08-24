//! System call invocation and correlated stack trace pipeline events.

/// Strongly-typed event representing a system call paired with its kernel stack trace.
#[derive(Debug, Clone)]
pub struct CorrelatedSyscallEvent {
    /// Operating system Process ID where the syscall occurred.
    pub pid: u32,
    /// Operating system Thread ID where the syscall occurred.
    pub tid: u32,
    /// Timestamp when the syscall was triggered.
    pub timestamp: i64,
    /// 64-bit kernel dispatch function address (SyscallAddress) from PerfInfo.
    pub syscall_address: Option<u64>,
    /// Correlated call stack instruction pointers (frames) from Stack_Walk telemetry.
    pub frames: Vec<u64>,
}

/// Strongly-typed event representing a standalone system call trigger without stack walk.
#[derive(Debug, Clone)]
pub struct SyscallEvent {
    /// Operating system Process ID where the syscall occurred.
    pub pid: u32,
    /// Operating system Thread ID where the syscall occurred.
    pub tid: u32,
    /// Event timestamp in FILETIME ticks.
    pub timestamp: i64,
    /// 64-bit kernel dispatch function address (SyscallAddress) from PerfInfo.
    pub syscall_address: Option<u64>,
}
