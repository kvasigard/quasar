//! Zero-copy MOF data-transfer schemas for the Windows System Logger / NT Kernel Logger.
//!
//! Each submodule decodes a specific kernel MOF event class (`Process`, `PerfInfo/SysCallEnter`,
//! and `StackWalk`) from either a borrowed [`RawEvent`](crate::sensors::etw::RawEvent) or a raw
//! byte slice using [`ByteCursor`](super::ByteCursor).

pub mod process;
pub mod stack_walk;
pub mod syscall;
