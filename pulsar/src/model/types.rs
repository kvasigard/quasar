//! Shared domain primitives and newtypes.
//!
//! This module contains core value objects used across both transient domain events
//! and persistent domain entities.

use std::fmt;
use windows_sys::Win32::Foundation::STATUS_CONTROL_C_EXIT;

/// Strongly-typed Process Identifier (PID).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProcessId(pub u32);

impl fmt::Display for ProcessId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Strongly-typed Windows Session Identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionId(pub u32);

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Kernel pointer address of the `EPROCESS` block uniquely identifying a process instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UniqueProcessKey(pub usize);

impl fmt::Display for UniqueProcessKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

/// Exit status outcome for terminated processes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExitStatus {
    /// Process completed execution successfully with exit code 0.
    Success,

    /// Process was forcefully terminated (killed, terminated via Ctrl+C / taskkill, or crashed).
    Terminated,

    /// Non-standard or explicit application return code.
    Other(i32),
}

impl From<i32> for ExitStatus {
    fn from(code: i32) -> Self {
        match code {
            0 => Self::Success,
            // STATUS_CONTROL_C_EXIT (0xC000013A = -1073741510) indicates forced termination
            STATUS_CONTROL_C_EXIT | 1 => Self::Terminated,
            other => Self::Other(other),
        }
    }
}

impl fmt::Display for ExitStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Success => write!(f, "SUCCESS (0)"),
            Self::Terminated => write!(f, "TERMINATED"),
            Self::Other(code) => write!(f, "EXIT_CODE ({:#x})", code),
        }
    }
}

/// Strongly-typed collection of instruction pointer addresses representing an execution call stack.
///
/// Captured via ETW kernel stack walking during security-sensitive events (such as Syscall entries,
/// Thread creation, or Image loads). Can be inspected by detection engines to identify unbacked code,
/// direct syscall stubs, or stack spoofing/tampering.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct StackTrace {
    /// Ordered list of virtual memory addresses (instruction pointers), from the caller frame
    /// down to the thread entry root.
    pub frames: Vec<u64>,
}

impl StackTrace {
    /// Creates a new `StackTrace` from a vector of raw instruction pointer addresses.
    pub fn new(frames: Vec<u64>) -> Self {
        Self { frames }
    }

    /// Returns a borrowed slice of the stack frame instruction pointer addresses.
    pub fn frames(&self) -> &[u64] {
        &self.frames
    }

    /// Returns the number of stack frames captured in this trace.
    pub fn len(&self) -> usize {
        self.frames.len()
    }

    /// Returns `true` if no frames were captured in this stack trace.
    pub fn is_empty(&self) -> bool {
        self.frames.is_empty()
    }
}

impl From<Vec<u64>> for StackTrace {
    fn from(frames: Vec<u64>) -> Self {
        Self { frames }
    }
}

impl fmt::Display for StackTrace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "StackTrace({} frames)", self.frames.len())
    }
}

