//! Shared memory ring buffer transport primitives and wire formats.

use core::sync::atomic::{AtomicU16, AtomicU64};

/// 32-bit magic framing signature for telemetry records ('QSAR').
pub const RECORD_MAGIC: u32 = 0x5153_4152;

#[repr(C, align(8))]
#[derive(Debug)]
pub struct RecordHeader {
    pub magic: u32,      // 0x5153_4152 ('QSAR')
    pub total_size: u32, // Header + trailing payload length (aligned to 8 bytes)
    pub sequence: u64,   // Monotonic sequence number
    pub timestamp: i64,  // QPC timestamp
    pub event_type: u16, // DriverEventType
    pub status: AtomicU16, // RecordStatus transition (Reserved -> Committed/Wrap)
    pub _reserved: u32,
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordStatus {
    Reserved = 0,  // Slot claimed by producer; payload write in progress
    Committed = 1, // Write completed and memory fence executed; ready to consume
    Wrap = 2,      // Sentinel indicating end of buffer; consumer must wrap to offset 0
}

/// Dedicated 4 KB status page shared between kernel driver and user mode for zero-syscall synchronization.
///
/// Both fields use [`AtomicU64`] to guarantee safe concurrent reads and stores across privilege
/// boundaries without acquiring kernel locks or issuing system calls.
#[repr(C, align(8))]
pub struct ConsumerStatusPage {
    /// Monotonic byte offset consumed and retired by the user-mode pipeline.
    pub user_tail: AtomicU64,
    /// Total cumulative events dropped due to buffer capacity exhaustion.
    pub dropped_events: AtomicU64,
}

impl Default for ConsumerStatusPage {
    fn default() -> Self {
        Self {
            user_tail: AtomicU64::new(0),
            dropped_events: AtomicU64::new(0),
        }
    }
}

impl TryFrom<u16> for RecordStatus {
    type Error = ();
    fn try_from(val: u16) -> Result<Self, Self::Error> {
        match val {
            0 => Ok(Self::Reserved),
            1 => Ok(Self::Committed),
            2 => Ok(Self::Wrap),
            _ => Err(()),
        }
    }
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriverEventType {
    HandlePreOperation = 1,
}

impl TryFrom<u16> for DriverEventType {
    type Error = ();
    fn try_from(val: u16) -> Result<Self, Self::Error> {
        match val {
            1 => Ok(Self::HandlePreOperation),
            _ => Err(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::{align_of, offset_of, size_of};

    #[test]
    fn test_record_header_layout() {
        assert_eq!(size_of::<RecordHeader>(), 32);
        assert_eq!(align_of::<RecordHeader>(), 8);
        assert_eq!(offset_of!(RecordHeader, magic), 0);
        assert_eq!(offset_of!(RecordHeader, total_size), 4);
        assert_eq!(offset_of!(RecordHeader, sequence), 8);
        assert_eq!(offset_of!(RecordHeader, timestamp), 16);
        assert_eq!(offset_of!(RecordHeader, event_type), 24);
        assert_eq!(offset_of!(RecordHeader, status), 26);
        assert_eq!(offset_of!(RecordHeader, _reserved), 28);
    }

    #[test]
    fn test_consumer_status_page_layout() {
        assert_eq!(size_of::<ConsumerStatusPage>(), 16);
        assert_eq!(align_of::<ConsumerStatusPage>(), 8);
        assert_eq!(offset_of!(ConsumerStatusPage, user_tail), 0);
        assert_eq!(offset_of!(ConsumerStatusPage, dropped_events), 8);
    }
}
