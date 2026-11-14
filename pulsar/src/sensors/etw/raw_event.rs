//! Zero-copy view over a raw Win32 `EVENT_RECORD` and its extended data items.
//!
//! [`RawEvent`] is a `#[repr(transparent)]` wrapper around [`EVENT_RECORD`] that allows
//! the ETW consumer callback and schema decoders to inspect headers, determine 32-bit vs.
//! 64-bit pointer sizes, slice `UserData`, and iterate `ExtendedData` without any heap
//! allocation.

use std::ffi::c_void;
use std::fmt;
use std::ops::Deref;
use std::slice;

use windows_sys::Win32::System::Diagnostics::Etw::{
    EVENT_HEADER_EXT_TYPE_PROCESS_START_KEY, EVENT_HEADER_EXT_TYPE_SID,
    EVENT_HEADER_EXT_TYPE_STACK_TRACE32, EVENT_HEADER_EXT_TYPE_STACK_TRACE64,
    EVENT_HEADER_EXTENDED_DATA_ITEM, EVENT_HEADER_FLAG_32_BIT_HEADER,
    EVENT_HEADER_FLAG_64_BIT_HEADER, EVENT_RECORD,
};
use windows_sys::core::GUID;

use crate::helpers::format_guid;

/// Zero-copy, `#[repr(transparent)]` wrapper over a Win32 [`EVENT_RECORD`].
///
/// A `&RawEvent` is valid for the duration of the `ProcessTrace` [`EventRecordCallback`]
/// invocation (or for the lifetime of a [`SyntheticEvent`] in tests).
#[repr(transparent)]
pub struct RawEvent(EVENT_RECORD);

impl RawEvent {
    /// Safely constructs a borrowed [`RawEvent`] reference from a raw [`EVENT_RECORD`] pointer.
    ///
    /// # Safety
    ///
    /// If `ptr` is non-null, it must point to a valid, initialized [`EVENT_RECORD`] whose
    /// `UserData` and `ExtendedData` buffers remain valid for lifetime `'a`.
    #[inline(always)]
    pub unsafe fn from_ptr<'a>(ptr: *const EVENT_RECORD) -> Option<&'a Self> {
        if ptr.is_null() {
            None
        } else {
            // SAFETY: `RawEvent` is `#[repr(transparent)]` over `EVENT_RECORD` and `ptr` is non-null.
            Some(unsafe { &*(ptr as *const Self) })
        }
    }

    /// Wraps an existing [`EVENT_RECORD`] reference as a [`RawEvent`] at zero cost.
    #[inline(always)]
    pub const fn from_ref(record: &EVENT_RECORD) -> &Self {
        // SAFETY: `RawEvent` is `#[repr(transparent)]` over `EVENT_RECORD`.
        unsafe { &*(record as *const EVENT_RECORD as *const Self) }
    }

    /// Returns a reference to the underlying Win32 [`EVENT_RECORD`].
    #[inline(always)]
    pub const fn as_raw(&self) -> &EVENT_RECORD {
        &self.0
    }

    /// Returns the GUID of the ETW provider that emitted this event.
    #[inline(always)]
    pub const fn provider_id(&self) -> &GUID {
        &self.0.EventHeader.ProviderId
    }

    /// Returns the 16-bit Event ID from the event descriptor.
    #[inline(always)]
    pub const fn event_id(&self) -> u16 {
        self.0.EventHeader.EventDescriptor.Id
    }

    /// Returns the schema version of the event.
    #[inline(always)]
    pub const fn version(&self) -> u8 {
        self.0.EventHeader.EventDescriptor.Version
    }

    /// Returns the event opcode (e.g., `Start = 1`, `End = 2`, `SysCallEnter = 51`).
    #[inline(always)]
    pub const fn opcode(&self) -> u8 {
        self.0.EventHeader.EventDescriptor.Opcode
    }

    /// Returns the severity level of the event.
    #[inline(always)]
    pub const fn level(&self) -> u8 {
        self.0.EventHeader.EventDescriptor.Level
    }

    /// Returns the 64-bit keyword bitmask of the event.
    #[inline(always)]
    pub const fn keyword(&self) -> u64 {
        self.0.EventHeader.EventDescriptor.Keyword
    }

    /// Returns the raw `EventHeader.Flags` bitmask.
    #[inline(always)]
    pub const fn flags(&self) -> u16 {
        self.0.EventHeader.Flags
    }

    /// Returns the Process ID (PID) recorded in the ETW header.
    #[inline(always)]
    pub const fn process_id(&self) -> u32 {
        self.0.EventHeader.ProcessId
    }

    /// Returns the Thread ID (TID) recorded in the ETW header.
    #[inline(always)]
    pub const fn thread_id(&self) -> u32 {
        self.0.EventHeader.ThreadId
    }

    /// Returns the raw timestamp of the event (QPC ticks or FileTime 100ns intervals).
    #[inline(always)]
    pub const fn timestamp(&self) -> i64 {
        self.0.EventHeader.TimeStamp
    }

    /// Returns the Activity ID GUID associated with the event.
    #[inline(always)]
    pub const fn activity_id(&self) -> &GUID {
        &self.0.EventHeader.ActivityId
    }

    /// Returns the logical processor index on which the event was logged.
    #[inline(always)]
    pub const fn processor_index(&self) -> u16 {
        // SAFETY: `BufferContext.Anonymous` and `ProcessorIndex` are plain integer union fields.
        unsafe { self.0.BufferContext.Anonymous.ProcessorIndex }
    }

    /// Returns `true` if the event was emitted by a 32-bit process (e.g. WOW64 on 64-bit Windows).
    #[inline(always)]
    pub const fn is_32bit(&self) -> bool {
        (self.0.EventHeader.Flags & (EVENT_HEADER_FLAG_32_BIT_HEADER as u16)) != 0
    }

    /// Returns the pointer byte width (`4` or `8`) of pointer-sized fields inside `user_data()`.
    ///
    /// Inspects `EVENT_HEADER_FLAG_32_BIT_HEADER` (`0x20`) and `EVENT_HEADER_FLAG_64_BIT_HEADER` (`0x40`)
    /// so WOW64 32-bit events on a 64-bit OS are parsed with 4-byte pointers. Falls back to the host
    /// architecture pointer width when neither header flag is set (such as in synthetic tests).
    #[inline(always)]
    pub const fn pointer_size(&self) -> usize {
        let flags = self.0.EventHeader.Flags;
        if (flags & (EVENT_HEADER_FLAG_32_BIT_HEADER as u16)) != 0 {
            4
        } else if (flags & (EVENT_HEADER_FLAG_64_BIT_HEADER as u16)) != 0 {
            8
        } else {
            std::mem::size_of::<usize>()
        }
    }

    /// Returns a zero-copy byte slice over the event's `UserData` payload.
    #[inline(always)]
    pub fn user_data(&self) -> &[u8] {
        let ptr = self.0.UserData as *const u8;
        let len = self.0.UserDataLength as usize;
        if ptr.is_null() || len == 0 {
            &[]
        } else {
            // SAFETY: ETW guarantees `UserData` is valid for `UserDataLength` bytes during the callback.
            unsafe { slice::from_raw_parts(ptr, len) }
        }
    }

    /// Returns a zero-copy slice of the `EVENT_HEADER_EXTENDED_DATA_ITEM` descriptors attached to this event.
    #[inline(always)]
    pub fn extended_data(&self) -> &[EVENT_HEADER_EXTENDED_DATA_ITEM] {
        let ptr = self.0.ExtendedData;
        let count = self.0.ExtendedDataCount as usize;
        if ptr.is_null() || count == 0 {
            &[]
        } else {
            // SAFETY: ETW guarantees `ExtendedData` is valid for `ExtendedDataCount` items during the callback.
            unsafe { slice::from_raw_parts(ptr, count) }
        }
    }

    /// Searches the event's `ExtendedData` array for the first item matching `ext_type` and returns its payload slice.
    #[inline]
    pub fn find_extended_data(&self, ext_type: u16) -> Option<&[u8]> {
        for item in self.extended_data() {
            if item.ExtType == ext_type {
                let data_ptr = item.DataPtr as usize as *const u8;
                let data_len = item.DataSize as usize;
                if !data_ptr.is_null() && data_len > 0 {
                    // SAFETY: `DataPtr` is guaranteed by ETW to point to `DataSize` bytes.
                    return Some(unsafe { slice::from_raw_parts(data_ptr, data_len) });
                }
            }
        }
        None
    }

    /// Extracts the 64-bit `ProcessStartKey` from `ExtendedData` (`EVENT_HEADER_EXT_TYPE_PROCESS_START_KEY`), if present.
    #[inline]
    pub fn process_start_key(&self) -> Option<u64> {
        let bytes = self.find_extended_data(EVENT_HEADER_EXT_TYPE_PROCESS_START_KEY as u16)?;
        if bytes.len() >= 8 {
            Some(u64::from_ne_bytes(bytes[..8].try_into().ok()?))
        } else {
            None
        }
    }

    /// Extracts the raw binary `SID` from `ExtendedData` (`EVENT_HEADER_EXT_TYPE_SID`), if present.
    ///
    /// Note: `EVENT_HEADER_EXT_TYPE_SID` precedes the `SID` with a `TOKEN_USER` structure (`2 * pointer_size` bytes).
    #[inline]
    pub fn extended_sid_bytes(&self) -> Option<&[u8]> {
        self.find_extended_data(EVENT_HEADER_EXT_TYPE_SID as u16)
    }

    /// Extracts an inline call stack from `ExtendedData` (`STACK_TRACE64` or `STACK_TRACE32`), if present.
    ///
    /// Note: The first 8 bytes of `EVENT_EXTENDED_ITEM_STACK_TRACE64` / `STACK_TRACE32` contain `MatchId: u64`,
    /// followed by the array of instruction pointer addresses.
    pub fn extract_call_stack(&self) -> Option<Vec<u64>> {
        for item in self.extended_data() {
            let data_ptr = item.DataPtr as usize as *const u8;
            let data_size = item.DataSize as usize;

            if data_ptr.is_null() || data_size <= 8 {
                continue;
            }

            let ext_type = item.ExtType as u32;
            if ext_type == EVENT_HEADER_EXT_TYPE_STACK_TRACE64 {
                let addr_bytes = data_size - 8;
                let count = addr_bytes / 8;
                if count == 0 {
                    continue;
                }
                // SAFETY: Skip 8-byte `MatchId` header and read `count` unaligned 64-bit addresses.
                let base = unsafe { data_ptr.add(8) as *const u64 };
                let mut stack = Vec::with_capacity(count);
                for i in 0..count {
                    stack.push(unsafe { base.add(i).read_unaligned() });
                }
                return Some(stack);
            } else if ext_type == EVENT_HEADER_EXT_TYPE_STACK_TRACE32 {
                let addr_bytes = data_size - 8;
                let count = addr_bytes / 4;
                if count == 0 {
                    continue;
                }
                // SAFETY: Skip 8-byte `MatchId` header and read `count` unaligned 32-bit addresses.
                let base = unsafe { data_ptr.add(8) as *const u32 };
                let mut stack = Vec::with_capacity(count);
                for i in 0..count {
                    stack.push(unsafe { base.add(i).read_unaligned() } as u64);
                }
                return Some(stack);
            }
        }
        None
    }
}

impl fmt::Debug for RawEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RawEvent")
            .field("provider_id", &format_guid(self.provider_id()))
            .field("event_id", &self.event_id())
            .field("version", &self.version())
            .field("opcode", &self.opcode())
            .field("level", &self.level())
            .field("process_id", &self.process_id())
            .field("thread_id", &self.thread_id())
            .field("timestamp", &self.timestamp())
            .field("pointer_size", &self.pointer_size())
            .field("user_data_len", &self.user_data().len())
            .finish()
    }
}

/// Owned builder and container for constructing synthetic [`RawEvent`] instances in unit and integration tests.
///
/// Holds a pinned heap slice (`Box<[u8]>`) and an optional `ExtendedData` buffer alongside an [`EVENT_RECORD`],
/// dereferencing directly to [`RawEvent`].
pub struct SyntheticEvent {
    record: EVENT_RECORD,
    _user_data: Box<[u8]>,
    _ext_items: Box<[EVENT_HEADER_EXTENDED_DATA_ITEM]>,
    _ext_payload: Box<[u8]>,
}

impl SyntheticEvent {
    /// Creates a new [`SyntheticEvent`] with the given header parameters and payload bytes.
    pub fn new(
        provider_id: GUID,
        version: u8,
        opcode: u8,
        process_id: u32,
        thread_id: u32,
        timestamp: i64,
        user_data: impl Into<Vec<u8>>,
    ) -> Self {
        let boxed_data: Box<[u8]> = user_data.into().into_boxed_slice();
        let mut record: EVENT_RECORD = unsafe { std::mem::zeroed() };
        record.EventHeader.ProviderId = provider_id;
        record.EventHeader.EventDescriptor.Version = version;
        record.EventHeader.EventDescriptor.Opcode = opcode;
        record.EventHeader.ProcessId = process_id;
        record.EventHeader.ThreadId = thread_id;
        record.EventHeader.TimeStamp = timestamp;
        record.EventHeader.Flags = if std::mem::size_of::<usize>() == 8 {
            EVENT_HEADER_FLAG_64_BIT_HEADER as u16
        } else {
            EVENT_HEADER_FLAG_32_BIT_HEADER as u16
        };

        if !boxed_data.is_empty() {
            record.UserData = boxed_data.as_ptr() as *mut c_void;
            record.UserDataLength = boxed_data.len() as u16;
        }

        Self {
            record,
            _user_data: boxed_data,
            _ext_items: Box::new([]),
            _ext_payload: Box::new([]),
        }
    }

    /// Sets the `EventDescriptor.Id` on this synthetic event.
    pub fn with_event_id(mut self, event_id: u16) -> Self {
        self.record.EventHeader.EventDescriptor.Id = event_id;
        self
    }

    /// Sets the `EventHeader.Flags` (e.g., `EVENT_HEADER_FLAG_32_BIT_HEADER` to simulate a WOW64 32-bit event).
    pub fn with_flags(mut self, flags: u16) -> Self {
        self.record.EventHeader.Flags = flags;
        self
    }

    /// Attaches a 64-bit inline `STACK_TRACE64` extended data item to this synthetic event.
    pub fn with_inline_stack64(mut self, frames: &[u64]) -> Self {
        let mut payload = Vec::with_capacity(8 + frames.len() * 8);
        payload.extend_from_slice(&0u64.to_ne_bytes()); // MatchId
        for &frame in frames {
            payload.extend_from_slice(&frame.to_ne_bytes());
        }
        let boxed_payload = payload.into_boxed_slice();

        let item = EVENT_HEADER_EXTENDED_DATA_ITEM {
            Reserved1: 0,
            ExtType: EVENT_HEADER_EXT_TYPE_STACK_TRACE64 as u16,
             Anonymous: unsafe { std::mem::zeroed() },
            DataSize: boxed_payload.len() as u16,
            DataPtr: boxed_payload.as_ptr() as usize as u64,
        };
        let boxed_items: Box<[EVENT_HEADER_EXTENDED_DATA_ITEM]> = Box::new([item]);

        self.record.ExtendedData = boxed_items.as_ptr() as *mut EVENT_HEADER_EXTENDED_DATA_ITEM;
        self.record.ExtendedDataCount = 1;
        self._ext_items = boxed_items;
        self._ext_payload = boxed_payload;
        self
    }

    /// Attaches a 32-bit inline `STACK_TRACE32` extended data item to this synthetic event.
    pub fn with_inline_stack32(mut self, frames: &[u32]) -> Self {
        let mut payload = Vec::with_capacity(8 + frames.len() * 4);
        payload.extend_from_slice(&0u64.to_ne_bytes()); // MatchId
        for &frame in frames {
            payload.extend_from_slice(&frame.to_ne_bytes());
        }
        let boxed_payload = payload.into_boxed_slice();

        let item = EVENT_HEADER_EXTENDED_DATA_ITEM {
            Reserved1: 0,
            ExtType: EVENT_HEADER_EXT_TYPE_STACK_TRACE32 as u16,
            Anonymous: unsafe { std::mem::zeroed() },
            DataSize: boxed_payload.len() as u16,
            DataPtr: boxed_payload.as_ptr() as usize as u64,
        };
        let boxed_items: Box<[EVENT_HEADER_EXTENDED_DATA_ITEM]> = Box::new([item]);

        self.record.ExtendedData = boxed_items.as_ptr() as *mut EVENT_HEADER_EXTENDED_DATA_ITEM;
        self.record.ExtendedDataCount = 1;
        self._ext_items = boxed_items;
        self._ext_payload = boxed_payload;
        self
    }

    /// Returns a borrowed [`RawEvent`] view of this synthetic event.
    #[inline(always)]
    pub fn as_raw_event(&self) -> &RawEvent {
        RawEvent::from_ref(&self.record)
    }
}

impl Deref for SyntheticEvent {
    type Target = RawEvent;

    #[inline(always)]
    fn deref(&self) -> &Self::Target {
        self.as_raw_event()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_GUID: GUID = GUID {
        data1: 0x3d6fa8d0,
        data2: 0xfe05,
        data3: 0x11d0,
        data4: [0x9d, 0xda, 0x00, 0xc0, 0x4f, 0xd7, 0xba, 0x7c],
    };

    #[test]
    fn test_raw_event_null_ptr_returns_none() {
        let res = unsafe { RawEvent::from_ptr(std::ptr::null()) };
        assert!(res.is_none());
    }

    #[test]
    fn test_raw_event_header_and_pointer_size_detection() {
        let evt64 = SyntheticEvent::new(TEST_GUID, 3, 1, 4321, 8765, 999_000, vec![1, 2, 3, 4])
            .with_event_id(10)
            .with_flags(EVENT_HEADER_FLAG_64_BIT_HEADER as u16);

        assert_eq!(evt64.provider_id().data1, 0x3d6fa8d0);
        assert_eq!(evt64.event_id(), 10);
        assert_eq!(evt64.version(), 3);
        assert_eq!(evt64.opcode(), 1);
        assert_eq!(evt64.process_id(), 4321);
        assert_eq!(evt64.thread_id(), 8765);
        assert_eq!(evt64.timestamp(), 999_000);
        assert!(!evt64.is_32bit());
        assert_eq!(evt64.pointer_size(), 8);
        assert_eq!(evt64.user_data(), &[1, 2, 3, 4]);

        let evt32 = evt64.with_flags(EVENT_HEADER_FLAG_32_BIT_HEADER as u16);
        assert!(evt32.is_32bit());
        assert_eq!(evt32.pointer_size(), 4);
    }

    #[test]
    fn test_raw_event_extended_stack_extraction_64_and_32() {
        let evt64 = SyntheticEvent::new(TEST_GUID, 2, 51, 1000, 2000, 12345, Vec::new())
            .with_inline_stack64(&[0x7FFB_1111_2222, 0x7FFB_3333_4444]);
        assert_eq!(
            evt64.extract_call_stack(),
            Some(vec![0x7FFB_1111_2222, 0x7FFB_3333_4444])
        );

        let evt32 = SyntheticEvent::new(TEST_GUID, 2, 51, 1000, 2000, 12345, Vec::new())
            .with_inline_stack32(&[0x7700_1111, 0x7700_2222]);
        assert_eq!(
            evt32.extract_call_stack(),
            Some(vec![0x7700_1111u64, 0x7700_2222u64])
        );
    }
}
