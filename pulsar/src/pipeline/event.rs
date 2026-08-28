//! Pipeline event definitions.

use crate::model::events::{ProcessEvent, SyscallEvent};
use crate::model::types::StackTrace;

/// Strongly-typed domain events flowing through the analytics pipeline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// Process lifecycle change or telemetry event.
    Process(ProcessEvent),

    /// Kernel system call execution event.
    Syscall(SyscallEvent),
}

impl Event {
    /// Returns the timestamp of this domain event.
    pub fn timestamp(&self) -> i64 {
        match self {
            Event::Process(e) => e.timestamp,
            Event::Syscall(e) => e.timestamp,
        }
    }

    /// Attaches or updates the call stack trace for this domain event.
    pub fn attach_stack_trace(&mut self, stack_trace: StackTrace) {
        match self {
            Event::Process(e) => e.stack_trace = Some(stack_trace),
            Event::Syscall(e) => e.stack_trace = Some(stack_trace),
        }
    }
}

