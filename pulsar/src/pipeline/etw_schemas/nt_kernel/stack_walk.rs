//! DTO definitions for ETW NT Kernel Logger Stack Walk events.
//!
//! Event types for ETW Kernel Stack Tracing (`StackWalkGuid` `{DEF2FE46-7BD6-4B80-BD94-F57FE20D0CE3}`):
//!
//! +-------+---------------------------------+----------------------------------------------------+-----------------------+
//! | Value | Constant / Event Name           | Description                                        | MOF Class             |
//! +-------+---------------------------------+----------------------------------------------------+-----------------------+
//! | 32    | EVENT_TRACE_TYPE_STACKWALK      | Call stack captured immediately after an event     | StackWalk_TypeGroup1  |
//! +-------+---------------------------------+----------------------------------------------------+-----------------------+
//!
//! Reference documentation:
//! <https://learn.microsoft.com/en-us/windows/win32/etw/stackwalk>

use std::mem::size_of;
use thiserror::Error;

/// Error type encountered while parsing StackWalk ETW DTO structures.
#[derive(Debug, Error)]
pub enum DtoStackWalkError {
    #[error("Buffer too short for StackWalk header (expected at least {0} bytes, got {1})")]
    HeaderTooShort(usize, usize),

    #[error("Buffer length is not aligned to pointer size: {0} bytes remaining")]
    UnalignedFrames(usize),
}

/// Raw zero-copy DTO for `StackWalk_TypeGroup1` (Opcode 32) event payload.
///
/// Emitted by the kernel logger when stack tracing is enabled for specific kernel events.
/// The `EventTimeStamp` matches the timestamp of the event that triggered the stack walk.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(non_snake_case, non_camel_case_types)]
pub struct StackWalk_TypeGroup1<'a> {

    /// Timestamp of the triggering event this stack trace is associated with.
    pub EventTimeStamp: u64,

    /// Process ID where the stack trace was captured.
    pub StackProcess: u32,

    /// Thread ID where the stack trace was captured.
    pub StackThread: u32,

    /// Array of instruction pointer addresses from caller to root (unaligned byte slice).
    pub RawFrames: &'a [u8],

    /// Number of pointer frames present in `RawFrames`.
    pub FrameCount: usize,
}

impl<'a> StackWalk_TypeGroup1<'a> {
    /// Iterates over the raw frame instruction pointers in the stack walk payload.
    pub fn iter_frames(&self) -> impl Iterator<Item = u64> + 'a {
        const PTR_SIZE: usize = size_of::<usize>();
        self.RawFrames.chunks_exact(PTR_SIZE).map(|chunk| {
            if PTR_SIZE == 8 {
                u64::from_ne_bytes(chunk.try_into().unwrap())
            } else {
                u32::from_ne_bytes(chunk.try_into().unwrap()) as u64
            }
        })
    }

    /// Collects the instruction pointer frames into a `Vec<u64>`.
    pub fn to_frames(&self) -> Vec<u64> {
        self.iter_frames().collect()
    }
}

impl<'a> TryFrom<&'a [u8]> for StackWalk_TypeGroup1<'a> {
    type Error = DtoStackWalkError;

    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        // Header: EventTimeStamp (8 bytes) + StackProcess (4 bytes) + StackThread (4 bytes) = 16 bytes
        const HEADER_SIZE: usize = 16;
        const PTR_SIZE: usize = size_of::<usize>();

        if bytes.len() < HEADER_SIZE {
            return Err(DtoStackWalkError::HeaderTooShort(HEADER_SIZE, bytes.len()));
        }

        let event_timestamp = u64::from_ne_bytes(bytes[0..8].try_into().unwrap());
        let stack_process = u32::from_ne_bytes(bytes[8..12].try_into().unwrap());
        let stack_thread = u32::from_ne_bytes(bytes[12..16].try_into().unwrap());

        let raw_frames = &bytes[HEADER_SIZE..];
        if raw_frames.len() % PTR_SIZE != 0 {
            return Err(DtoStackWalkError::UnalignedFrames(raw_frames.len()));
        }

        let frame_count = raw_frames.len() / PTR_SIZE;

        Ok(Self {
            EventTimeStamp: event_timestamp,
            StackProcess: stack_process,
            StackThread: stack_thread,
            RawFrames: raw_frames,
            FrameCount: frame_count,
        })
    }
}
