//! Shared memory ring buffer transport primitives and wire formats.

#[repr(C, align(8))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordHeader {
    pub magic: u32,      // 0x5153_4152 ('QSAR')
    pub total_size: u32, // Header + trailing payload length (aligned to 8 bytes)
    pub sequence: u64,   // Monotonic sequence number
    pub timestamp: i64,  // QPC timestamp
    pub event_type: u16, // DriverEventType
    pub status: u16,     // RecordStatus (AtomicU16 transition)
    pub _reserved: u32,
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordStatus {
    Reserved = 0,  // Slot claimed by producer; payload write in progress
    Committed = 1, // Write completed and memory fence executed; ready to consume
    Wrap = 2,      // Sentinel indicating end of buffer; consumer must wrap to offset 0
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConsumerStatusPage {
    pub user_tail: u64,      // Monotonic byte offset consumed by user mode
    pub dropped_events: u64, // Total dropped events due to buffer full
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
