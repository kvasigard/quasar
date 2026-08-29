//! Safe, owned representation of ETW events and extended stack payloads.

use crate::helpers::format_guid;
use std::fmt;
use std::slice;
use windows_sys::Win32::System::Diagnostics::Etw::{
    EVENT_HEADER_EXT_TYPE_STACK_TRACE32, EVENT_HEADER_EXT_TYPE_STACK_TRACE64,
    EVENT_HEADER_EXTENDED_DATA_ITEM, EVENT_RECORD,
};
use windows_sys::core::GUID;

/// An owned, thread-safe representation of an ETW Event.
///
/// Copies essential telemetry data from raw C-pointers provided by the ETW callback
/// so that it can be safely sent across thread boundaries to the dispatcher.
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

// Manually implement Debug to format the GUID and preview UserData payload
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
    /// Constructs a safe, owned `EventRecord` by copying data from a raw ETW `EVENT_RECORD`.
    ///
    /// # Arguments
    ///
    /// * `raw_record` - Pointer to the raw Win32 `EVENT_RECORD`.
    ///
    /// # Returns
    ///
    /// `Some(EventRecord)` if the pointer is non-null and successfully parsed, otherwise `None`.
    ///
    /// # Safety
    ///
    /// The `raw_record` pointer must be a valid, readable pointer to an `EVENT_RECORD`
    /// provided by the Win32 `ProcessTrace` callback.
    pub unsafe fn from_raw(raw_record: *const EVENT_RECORD) -> Option<Self> {
        if raw_record.is_null() {
            return None;
        }

        // SAFETY: Verified non-null pointer above.
        let record = unsafe { &*raw_record };
        let header = &record.EventHeader;
        let descriptor = &header.EventDescriptor;

        // Extract the variable-length UserData payload into an owned Vec<u8>
        let user_data = if !record.UserData.is_null() && record.UserDataLength > 0 {
            // SAFETY: Verified non-null and valid length.
            unsafe {
                let slice = slice::from_raw_parts(
                    record.UserData as *const u8,
                    record.UserDataLength as usize,
                );
                slice.to_vec()
            }
        } else {
            Vec::new()
        };

        let mut stack_trace = None;

        if record.ExtendedDataCount > 0 && !record.ExtendedData.is_null() {
            unsafe {
                let ext_data_slice = slice::from_raw_parts(
                    record.ExtendedData as *const EVENT_HEADER_EXTENDED_DATA_ITEM,
                    record.ExtendedDataCount as usize,
                );

                for item in ext_data_slice {
                    // Match 64-bit stack traces
                    if item.ExtType == EVENT_HEADER_EXT_TYPE_STACK_TRACE64 as u16 {
                        let data_size = item.DataSize as usize;
                        // Minimum size is 8 bytes for the MatchId
                        if data_size > 8 {
                            let num_addresses = (data_size - 8) / std::mem::size_of::<u64>();
                            // Skip the 8-byte MatchId to get directly to the addresses
                            let ptr = (item.DataPtr as *const u8).add(8) as *const u64;
                            stack_trace = Some(slice::from_raw_parts(ptr, num_addresses).to_vec());
                            break;
                        }
                    }
                    // Match 32-bit stack traces
                    else if item.ExtType == EVENT_HEADER_EXT_TYPE_STACK_TRACE32 as u16 {
                        let data_size = item.DataSize as usize;
                        if data_size > 8 {
                            let num_addresses = (data_size - 8) / std::mem::size_of::<u32>();
                            let ptr = (item.DataPtr as *const u8).add(8) as *const u32;
                            let addresses = slice::from_raw_parts(ptr, num_addresses);
                            // Cast 32-bit addresses to u64 to unify the return type
                            stack_trace = Some(addresses.iter().map(|&addr| addr as u64).collect());
                            break;
                        }
                    }
                }
            }
        }

        Some(Self {
            provider_id: header.ProviderId,
            event_id: descriptor.Id,
            version: descriptor.Version,
            opcode: descriptor.Opcode,
            level: descriptor.Level,
            process_id: header.ProcessId,
            thread_id: header.ThreadId,
            timestamp: header.TimeStamp,
            user_data,
            stack_trace,
        })
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
        stack_payload.extend_from_slice(&0x7FFF_1111_2222_u64.to_ne_bytes());      // Frame 1
        stack_payload.extend_from_slice(&0x7FFF_3333_4444_u64.to_ne_bytes());      // Frame 2

        let mut ext_item: EVENT_HEADER_EXTENDED_DATA_ITEM = unsafe { std::mem::zeroed() };
        ext_item.ExtType = EVENT_HEADER_EXT_TYPE_STACK_TRACE64 as u16;
        ext_item.DataSize = stack_payload.len() as u16;
        ext_item.DataPtr = stack_payload.as_ptr() as u64;

        let mut raw_record: EVENT_RECORD = unsafe { std::mem::zeroed() };
        raw_record.EventHeader.Size = std::mem::size_of::<EVENT_HEADER>() as u16;
        raw_record.EventHeader.ThreadId = 1234;
        raw_record.EventHeader.ProcessId = 5678;
        raw_record.EventHeader.TimeStamp = 99999;
        raw_record.EventHeader.ProviderId = GUID { data1: 0x1234, data2: 0, data3: 0, data4: [0; 8] };
        raw_record.EventHeader.EventDescriptor = EVENT_DESCRIPTOR { Id: 1, Version: 2, Channel: 0, Level: 0, Opcode: 1, Task: 0, Keyword: 0 };
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

