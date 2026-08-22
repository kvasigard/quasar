//! Process domain pipeline events.

use crate::context::identity::ProcessKey;

/// Strongly-typed event representing a process creation or initial rundown discovery.
#[derive(Debug, Clone)]
pub struct ProcessStartEvent {
    /// Synthetic unique key assigned to this process instance.
    pub key: ProcessKey,
    /// Operating system Process ID (PID).
    pub pid: u32,
    /// Operating system Parent Process ID (PPID).
    pub parent_pid: u32,
    /// Parent synthetic key if resolved.
    pub parent_key: Option<ProcessKey>,
    /// Session ID where the process is active.
    pub session_id: u32,
    /// Executable image file name (e.g. "powershell.exe").
    pub image_file_name: String,
    /// Process command line invocation string if available.
    pub command_line: Option<String>,
    /// Event timestamp (FILETIME 100ns ticks).
    pub timestamp: i64,
}

/// Strongly-typed event representing a process termination.
#[derive(Debug, Clone)]
pub struct ProcessExitEvent {
    /// Synthetic unique key of the exiting process.
    pub key: ProcessKey,
    /// Operating system Process ID (PID).
    pub pid: u32,
    /// Win32 / NTSTATUS exit code.
    pub exit_status: u32,
    /// Event timestamp (FILETIME 100ns ticks).
    pub timestamp: i64,
}
