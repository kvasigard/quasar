//! Normalized pipeline domain events and telemetry types.

use crate::context::identity::ProcessKey;
use crate::context::models::module::LoadedModule;

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

/// Strongly-typed event representing a DLL or binary mapped into memory.
#[derive(Debug, Clone)]
pub struct ImageLoadEvent {
    /// Synthetic unique key of the process loading the module.
    pub process_key: ProcessKey,
    /// Operating system Process ID (PID).
    pub pid: u32,
    /// Loaded module metadata.
    pub module: LoadedModule,
    /// Event timestamp (FILETIME 100ns ticks).
    pub timestamp: i64,
}

/// Strongly-typed event representing a DLL or binary unmapped from memory.
#[derive(Debug, Clone)]
pub struct ImageUnloadEvent {
    /// Synthetic unique key of the process unmapping the module.
    pub process_key: ProcessKey,
    /// Operating system Process ID (PID).
    pub pid: u32,
    /// Virtual base address of the unmapped image.
    pub base_address: u64,
    /// Event timestamp (FILETIME 100ns ticks).
    pub timestamp: i64,
}

/// Strongly-typed event representing a system call paired with its kernel stack trace.
#[derive(Debug, Clone)]
pub struct CorrelatedSyscallEvent {
    /// Operating system Process ID where the syscall occurred.
    pub pid: u32,
    /// Operating system Thread ID where the syscall occurred.
    pub tid: u32,
    /// Timestamp when the syscall was triggered.
    pub timestamp: i64,
    /// System call number / service index if available from PerfInfo.
    pub syscall_number: Option<u32>,
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
    /// System call service index number.
    pub syscall_number: Option<u32>,
}

/// Universal event enum flowing through the detection and processing pipeline.
///
/// Every event is a strongly-typed domain struct. Raw sensor bytes are never exposed to detection sinks.
#[derive(Debug, Clone)]
pub enum Event {
    /// Process creation event.
    ProcessStart(ProcessStartEvent),
    /// Process termination event.
    ProcessExit(ProcessExitEvent),
    /// Dynamic library / executable module mapped into memory.
    ImageLoad(ImageLoadEvent),
    /// Dynamic library / module unmapped from memory.
    ImageUnload(ImageUnloadEvent),
    /// System call correlated with its complete call stack trace.
    CorrelatedSyscall(CorrelatedSyscallEvent),
    /// Standalone system call event.
    Syscall(SyscallEvent),
}
