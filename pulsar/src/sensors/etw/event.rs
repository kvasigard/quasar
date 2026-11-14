//! Safe, owned representation of ETW events and extended stack payloads.

use std::fmt;
use windows_sys::Win32::System::Diagnostics::Etw::{
    EVENT_HEADER_FLAG_32_BIT_HEADER, EVENT_HEADER_FLAG_64_BIT_HEADER, EVENT_RECORD,
};
use windows_sys::core::GUID;

use crate::helpers::format_guid;
use crate::sensors::etw::raw_event::{RawEvent, SyntheticEvent};

/// An owned, thread-safe representation of an ETW Event.
///
/// Copies essential telemetry data from raw C-pointers provided by the ETW callback
/// when an owned buffer is required. For zero-copy in-callback decoding, prefer [`RawEvent`].
#[derive(Clone)]
pub struct EventRecord {
    /// The GUID of the ETW Provider that emitted this event.
    pub provider_id: GUID,
    /// The Event ID, identifying the specific event type.
    pub event_id: u16,
    /// The version of the event schema.
    pub version: u8,
    /// The opcode defining the action (e.g. Start, Stop, DCStart).
    pub opcode: u8,
    /// The severity level of the event.
    pub level: u8,
    /// The Process ID (PID) that generated the event.
    pub process_id: u32,
    /// The Thread ID (TID) that generated the event.
    pub thread_id: u32,
    /// The timestamp of the event (typically 100ns intervals since 1601 or QPC tick).
    pub timestamp: i64,
    /// The raw payload of the event.
    pub user_data: Vec<u8>,
    /// Extracted user/kernel stack instruction pointers from ExtendedData.
    pub stack_trace: Option<Vec<u64>>,
}

impl fmt::Debug for EventRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let peek_len = std::cmp::min(self.user_data.len(), 32);
        let user_data_hex = self.user_data[..peek_len]
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<String>>()
            .join(" ");

        f.debug_struct("EventRecord")
            .field("provider_id", &format_guid(&self.provider_id))
            .field("opcode", &self.opcode)
            .field("process_id", &self.process_id)
            .field("thread_id", &self.thread_id)
            .field("user_data_len", &self.user_data.len())
            .field("user_data_peek", &user_data_hex)
            .finish()
    }
}

impl EventRecord {
    /// Constructs a safe, owned `EventRecord` from a borrowed [`RawEvent`].
    #[inline]
    pub fn from_raw_event(raw: &RawEvent) -> Self {
        Self {
            provider_id: *raw.provider_id(),
            event_id: raw.event_id(),
            version: raw.version(),
            opcode: raw.opcode(),
            level: raw.level(),
            process_id: raw.process_id(),
            thread_id: raw.thread_id(),
            timestamp: raw.timestamp(),
            user_data: raw.user_data().to_vec(),
            stack_trace: raw.extract_call_stack(),
        }
    }

    /// Constructs a safe, owned `EventRecord` by copying data from a raw ETW `EVENT_RECORD` pointer.
    ///
    /// # Safety
    ///
    /// The `raw_record` pointer must be a valid, readable pointer to an `EVENT_RECORD`
    /// provided by the Win32 `ProcessTrace` callback.
    #[inline]
    pub unsafe fn from_raw(raw_record: *const EVENT_RECORD) -> Option<Self> {
        let raw = unsafe { RawEvent::from_ptr(raw_record) }?;
        Some(Self::from_raw_event(raw))
    }

    /// Returns the host pointer size (`4` or `8` bytes) for this record.
    #[inline(always)]
    pub const fn pointer_size(&self) -> usize {
        std::mem::size_of::<usize>()
    }

    /// Converts this owned [`EventRecord`] into a [`SyntheticEvent`] that dereferences to [`RawEvent`].
    pub fn to_synthetic_event(&self) -> SyntheticEvent {
        let flags = if std::mem::size_of::<usize>() == 8 {
            EVENT_HEADER_FLAG_64_BIT_HEADER as u16
        } else {
            EVENT_HEADER_FLAG_32_BIT_HEADER as u16
        };
        let mut syn = SyntheticEvent::new(
            self.provider_id,
            self.version,
            self.opcode,
            self.process_id,
            self.thread_id,
            self.timestamp,
            self.user_data.clone(),
        )
        .with_event_id(self.event_id)
        .with_flags(flags);

        if let Some(ref frames) = self.stack_trace {
            syn = syn.with_inline_stack64(frames);
        }
        syn
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::System::Diagnostics::Etw::{
        EVENT_DESCRIPTOR, EVENT_HEADER, EVENT_HEADER_EXT_TYPE_STACK_TRACE64,
        EVENT_HEADER_EXTENDED_DATA_ITEM, EVENT_RECORD,
    };

    /// Asserts that null pointers passed to from_raw return None safely without triggering null pointer dereferences.
    /// Essential safety boundary check for the raw C-ABI ETW callback invoked asynchronously by the OS kernel.
    #[test]
    fn test_event_record_from_raw_null_pointer() {
        let result = unsafe { EventRecord::from_raw(std::ptr::null()) };
        assert!(result.is_none());
    }

    /// Verifies parsing of ExtendedData 64-bit stack payloads, confirming the 8-byte MatchId header is skipped.
    /// Critical to ensure instruction pointer frames extracted from ETW extended buffers represent actual caller frames.
    #[test]
    fn test_event_record_from_raw_with_extended_stack64() {
        let mut stack_payload = Vec::new();
        stack_payload.extend_from_slice(&0xDEAD_BEEF_CAFE_BABE_u64.to_ne_bytes()); // 8-byte MatchId
        stack_payload.extend_from_slice(&0x7FFF_1111_2222_u64.to_ne_bytes()); // Frame 1
        stack_payload.extend_from_slice(&0x7FFF_3333_4444_u64.to_ne_bytes()); // Frame 2

        let mut ext_item: EVENT_HEADER_EXTENDED_DATA_ITEM = unsafe { std::mem::zeroed() };
        ext_item.ExtType = EVENT_HEADER_EXT_TYPE_STACK_TRACE64 as u16;
        ext_item.DataSize = stack_payload.len() as u16;
        ext_item.DataPtr = stack_payload.as_ptr() as u64;

        let mut raw_record: EVENT_RECORD = unsafe { std::mem::zeroed() };
        raw_record.EventHeader.Size = std::mem::size_of::<EVENT_HEADER>() as u16;
        raw_record.EventHeader.ThreadId = 1234;
        raw_record.EventHeader.ProcessId = 5678;
        raw_record.EventHeader.TimeStamp = 99999;
        raw_record.EventHeader.ProviderId = GUID {
            data1: 0x1234,
            data2: 0,
            data3: 0,
            data4: [0; 8],
        };
        raw_record.EventHeader.EventDescriptor = EVENT_DESCRIPTOR {
            Id: 1,
            Version: 2,
            Channel: 0,
            Level: 0,
            Opcode: 1,
            Task: 0,
            Keyword: 0,
        };
        raw_record.ExtendedDataCount = 1;
        raw_record.ExtendedData = &ext_item as *const _ as *mut _;

        let parsed = unsafe { EventRecord::from_raw(&raw_record) }.expect("Record must parse");
        assert_eq!(parsed.process_id, 5678);
        assert_eq!(
            parsed.stack_trace,
            Some(vec![0x7FFF_1111_2222, 0x7FFF_3333_4444])
        );
    }
}
