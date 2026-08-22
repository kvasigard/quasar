//! Domain-partitioned pipeline domain events and universal telemetry types.

pub mod file;
pub mod image;
pub mod process;
pub mod syscall;

pub use file::{FileCreateEvent, FileIoEvent, FileOperationEvent, FileReadWriteEvent};
pub use image::{ImageLoadEvent, ImageUnloadEvent};
pub use process::{ProcessExitEvent, ProcessStartEvent};
pub use syscall::{CorrelatedSyscallEvent, SyscallEvent};

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
    /// Filesystem file I/O event.
    FileIo(FileIoEvent),
}
