//! Zero-copy MOF DTO and decoded event definitions for Windows Kernel `StackWalk` events (`StackWalk_TypeGroup1`).
//!
//! # Event Opcodes & MOF Classes (`StackWalkGuid` `{def2fe46-7bd6-4b80-bd94-f57fe20d0ce3}`)
//!
//! | Opcode | Constant / Event Name        | Description                                    | MOF Class             |
//! |--------|------------------------------|------------------------------------------------|-----------------------|
//! | `32`   | `EVENT_TRACE_TYPE_STACKWALK` | Call stack captured immediately after an event | `StackWalk_TypeGroup1` |
//!
//! # Correlation Mechanism
//!
//! When kernel stack tracing is enabled for a classic MOF event via
//! `TraceSetInformation(TraceStackTracingInfo)`, the kernel emits a `StackWalk_TypeGroup1`
//! record whose `EventTimeStamp`, `StackProcess`, and `StackThread` fields match the
//! `EventHeader.TimeStamp`, `ProcessId`, and `ThreadId` of the triggering event.
//!
//! Reference: <https://learn.microsoft.com/en-us/windows/win32/etw/stackwalk>

use thiserror::Error;

use crate::model::types::StackTrace;
use crate::pipeline::etw_schemas::cursor::ByteCursor;
use crate::sensors::etw::RawEvent;

/// Errors encountered while decoding a `StackWalk_TypeGroup1` (Opcode 32) payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum DtoStackWalkError {
    /// The `UserData` buffer was shorter than the mandatory 16-byte fixed header (`EventTimeStamp + StackProcess + StackThread`).
    #[error("Buffer too short for StackWalk header (expected at least {0} bytes, got {1})")]
    HeaderTooShort(usize, usize),

    /// The trailing `Stack1..StackN` byte slice was not a multiple of the event's pointer size (`4` or `8` bytes).
    #[error("Buffer length is not aligned to pointer size: {0} bytes remaining")]
    UnalignedFrames(usize),
}

/// Borrowed zero-copy DTO for `StackWalk_TypeGroup1` (Opcode 32) MOF payload.
///
/// Slices the trailing instruction pointer array (`RawFrames`) directly from the ETW buffer
/// without allocating a `Vec<u64>` until [`Self::to_frames`] is called.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(non_snake_case, non_camel_case_types)]
pub struct StackWalk_TypeGroup1<'a> {
    /// Raw QPC timestamp of the triggering kernel event this stack trace belongs to.
    pub EventTimeStamp: u64,

    /// Process ID (`PID`) in which the stack trace was captured.
    pub StackProcess: u32,

    /// Thread ID (`TID`) in which the stack trace was captured.
    pub StackThread: u32,

    /// Borrowed byte slice of instruction pointer frames (`FrameCount * PointerSize` bytes).
    pub RawFrames: &'a [u8],

    /// Number of instruction pointer frames present in `RawFrames`.
    pub FrameCount: usize,

    /// Byte width (`4` or `8`) of each instruction pointer frame in `RawFrames`.
    pub PointerSize: usize,
}

impl<'a> StackWalk_TypeGroup1<'a> {
    /// Parses a `StackWalk_TypeGroup1` payload from a bitness-aware [`ByteCursor`].
    #[inline]
    pub fn parse(cursor: &mut ByteCursor<'a>) -> Result<Self, DtoStackWalkError> {
        const HEADER_SIZE: usize = 16;
        let ptr_size = cursor.pointer_size();
        let total_len = cursor.remaining();

        if total_len < HEADER_SIZE {
            return Err(DtoStackWalkError::HeaderTooShort(HEADER_SIZE, total_len));
        }

        let event_timestamp = cursor.read_u64("EventTimeStamp").unwrap();
        let stack_process = cursor.read_u32("StackProcess").unwrap();
        let stack_thread = cursor.read_u32("StackThread").unwrap();

        let raw_frames = cursor.remaining_slice();
        if !raw_frames.len().is_multiple_of(ptr_size) {
            return Err(DtoStackWalkError::UnalignedFrames(raw_frames.len()));
        }

        let frame_count = raw_frames.len() / ptr_size;

        Ok(Self {
            EventTimeStamp: event_timestamp,
            StackProcess: stack_process,
            StackThread: stack_thread,
            RawFrames: raw_frames,
            FrameCount: frame_count,
            PointerSize: ptr_size,
        })
    }

    /// Returns an alignment-safe iterator over the instruction pointer frames in `RawFrames`
    /// (zero-extending 32-bit frames to `u64`).
    pub fn iter_frames(&self) -> impl Iterator<Item = u64> + 'a {
        let ptr_size = self.PointerSize;
        self.RawFrames.chunks_exact(ptr_size).map(move |chunk| {
            if ptr_size == 8 {
                u64::from_ne_bytes(chunk.try_into().unwrap())
            } else {
                u32::from_ne_bytes(chunk.try_into().unwrap()) as u64
            }
        })
    }

    /// Collects the instruction pointer frames into an owned `Vec<u64>`.
    pub fn to_frames(&self) -> Vec<u64> {
        self.iter_frames().collect()
    }
}

impl<'a> TryFrom<&'a [u8]> for StackWalk_TypeGroup1<'a> {
    type Error = DtoStackWalkError;

    #[inline]
    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        Self::parse(&mut ByteCursor::new(bytes))
    }
}

impl<'a> TryFrom<&'a RawEvent> for StackWalk_TypeGroup1<'a> {
    type Error = DtoStackWalkError;

    #[inline]
    fn try_from(event: &'a RawEvent) -> Result<Self, Self::Error> {
        Self::parse(&mut ByteCursor::from_raw_event(event))
    }
}

/// Owned, pre-decoded out-of-band kernel stack walk event sent inside
/// [`TelemetryEnvelope::StackWalk`](crate::pipeline::TelemetryEnvelope::StackWalk) to
/// [`CallStackCorrelator`](crate::pipeline::CallStackCorrelator).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StackWalkEvent {
    /// Timestamp (`EventTimeStamp`) of the triggering kernel event.
    pub event_timestamp: u64,
    /// Target Process ID (`StackProcess`).
    pub process_id: u32,
    /// Target Thread ID (`StackThread`).
    pub thread_id: u32,
    /// Extracted instruction pointer call stack.
    pub stack_trace: StackTrace,
}

impl TryFrom<&RawEvent> for StackWalkEvent {
    type Error = DtoStackWalkError;

    #[inline]
    fn try_from(event: &RawEvent) -> Result<Self, Self::Error> {
        let dto = StackWalk_TypeGroup1::try_from(event)?;
        Ok(Self {
            event_timestamp: dto.EventTimeStamp,
            process_id: dto.StackProcess,
            thread_id: dto.StackThread,
            stack_trace: StackTrace::new(dto.to_frames()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verifies extraction of correlation timestamp, thread context, and multi-frame call stack unwinding from raw ETW payloads.
    /// Mandatory to ensure the call stack correlator receives exact 64-bit frame addresses without truncation or byte transposition.
    #[test]
    fn test_stack_walk_dto_parsing_and_frame_iteration() {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&123_456_789u64.to_ne_bytes()); // EventTimeStamp
        buffer.extend_from_slice(&4321u32.to_ne_bytes()); // StackProcess
        buffer.extend_from_slice(&8765u32.to_ne_bytes()); // StackThread

        let frames: [usize; 3] = [0x7FFF_0001, 0x7FFF_0002, 0x7FFF_0003];
        for f in &frames {
            buffer.extend_from_slice(&f.to_ne_bytes());
        }

        let dto =
            StackWalk_TypeGroup1::try_from(buffer.as_slice()).expect("Valid StackWalk must parse");
        assert_eq!(dto.EventTimeStamp, 123_456_789);
        assert_eq!(dto.StackProcess, 4321);
        assert_eq!(dto.StackThread, 8765);
        assert_eq!(dto.FrameCount, 3);
        assert_eq!(
            dto.to_frames(),
            vec![0x7FFF_0001u64, 0x7FFF_0002u64, 0x7FFF_0003u64]
        );
    }

    /// Asserts rejection of truncated headers and non-pointer-aligned trailing byte arrays.
    /// Protects against memory corruption when kernel stack buffer flushes are interrupted mid-write.
    #[test]
    fn test_stack_walk_dto_unaligned_or_truncated_header() {
        // Less than 16-byte fixed header
        let truncated = vec![0u8; 15];
        assert!(matches!(
            StackWalk_TypeGroup1::try_from(truncated.as_slice()),
            Err(DtoStackWalkError::HeaderTooShort(16, 15))
        ));

        // 16-byte header + 3 unaligned bytes
        let mut unaligned = vec![0u8; 16];
        unaligned.extend_from_slice(&[1, 2, 3]);
        assert!(matches!(
            StackWalk_TypeGroup1::try_from(unaligned.as_slice()),
            Err(DtoStackWalkError::UnalignedFrames(3))
        ));
    }
}
