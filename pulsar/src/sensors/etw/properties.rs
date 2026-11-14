//! Safe RAII memory management for Win32 `EVENT_TRACE_PROPERTIES` / `EVENT_TRACE_PROPERTIES_V2`
//! and kernel trace session statistics.

use std::mem::size_of;
use windows_sys::Win32::System::Diagnostics::Etw::{
    EVENT_TRACE_PROPERTIES, EVENT_TRACE_PROPERTIES_V2, EVENT_TRACE_REAL_TIME_MODE,
    WNODE_FLAG_TRACED_GUID, WNODE_FLAG_VERSIONED_PROPERTIES,
};
use windows_sys::core::GUID;

use super::masks::PerfGroupMask;
use super::session::EventTraceProperties;

/// Extension item type ID for `PERFINFO_GROUPMASK` inside `EVENT_TRACE_PROPERTIES_V2.FilterDesc` / V2 extension blocks.
const ETW_EXT_ENABLE_FLAGS: u16 = 1;

/// Kernel-level ring buffer and event loss statistics returned by `ControlTraceW`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TraceStatistics {
    /// Total number of buffers allocated for the ETW session pool.
    pub number_of_buffers: u32,
    /// Number of buffers that are idle and available in the pool.
    pub free_buffers: u32,
    /// Number of events dropped by the kernel because all ring buffers were full.
    pub events_lost: u32,
    /// Total number of buffers flushed/written since the session started.
    pub buffers_written: u32,
    /// Number of file-backed buffers dropped.
    pub log_buffers_lost: u32,
    /// Number of real-time consumer buffers dropped before user-mode could drain them.
    pub real_time_buffers_lost: u32,
}

impl TraceStatistics {
    /// Returns `true` if any events or real-time buffers were lost during the trace session.
    #[inline]
    pub const fn has_drops(&self) -> bool {
        self.events_lost > 0 || self.real_time_buffers_lost > 0 || self.log_buffers_lost > 0
    }
}

/// RAII memory manager for Win32 `EVENT_TRACE_PROPERTIES` and `EVENT_TRACE_PROPERTIES_V2`.
///
/// Windows requires `EVENT_TRACE_PROPERTIES[_V2]`, any V2 extension items, and trailing UTF-16
/// strings (`LoggerName`, `LogFileName`) to reside in a single contiguous, 8-byte-aligned block
/// of memory.
pub struct TracePropertiesBuffer {
    buffer: Vec<u64>,
}

impl TracePropertiesBuffer {
    /// Allocates and initializes an aligned `EVENT_TRACE_PROPERTIES` buffer with trailing UTF-16 strings.
    pub fn new(
        session_name: &str,
        properties: &EventTraceProperties,
        session_guid: GUID,
        enable_flags: u32,
    ) -> Self {
        let name_wide: Vec<u16> = session_name.encode_utf16().chain(Some(0)).collect();
        let file_wide: Vec<u16> = properties
            .log_file_name
            .as_ref()
            .map(|s| s.encode_utf16().chain(Some(0)).collect())
            .unwrap_or_default();

        let struct_size = size_of::<EVENT_TRACE_PROPERTIES>();
        let name_len_bytes = name_wide.len() * size_of::<u16>();
        let file_len_bytes = file_wide.len() * size_of::<u16>();

        let total_size = struct_size + name_len_bytes + file_len_bytes;
        let u64_len = total_size.div_ceil(size_of::<u64>());
        let mut buffer = vec![0u64; u64_len];
        let base_byte_ptr = buffer.as_mut_ptr() as *mut u8;
        let props_ptr = base_byte_ptr as *mut EVENT_TRACE_PROPERTIES;

        // SAFETY: The buffer is 8-byte aligned via `Vec<u64>` and allocated with at least `total_size` bytes.
        unsafe {
            (*props_ptr).Wnode.BufferSize = (u64_len * size_of::<u64>()) as u32;
            (*props_ptr).Wnode.Flags = WNODE_FLAG_TRACED_GUID;
            (*props_ptr).Wnode.ClientContext = 1; // QPC timestamp
            (*props_ptr).Wnode.Guid = session_guid;

            let mut log_mode = properties.log_file_mode;
            if log_mode == 0 && file_wide.is_empty() {
                log_mode = EVENT_TRACE_REAL_TIME_MODE;
            }

            (*props_ptr).LogFileMode = log_mode;
            (*props_ptr).BufferSize = properties.buffer_size;
            (*props_ptr).MinimumBuffers = properties.minimum_buffers;
            (*props_ptr).MaximumBuffers = properties.maximum_buffers;
            (*props_ptr).FlushTimer = properties.flush_timer;
            (*props_ptr).EnableFlags = enable_flags;
            (*props_ptr).LoggerNameOffset = struct_size as u32;

            if !file_wide.is_empty() {
                (*props_ptr).LogFileNameOffset = (struct_size + name_len_bytes) as u32;
            }

            std::ptr::copy_nonoverlapping(
                name_wide.as_ptr(),
                base_byte_ptr.add(struct_size) as *mut u16,
                name_wide.len(),
            );

            if !file_wide.is_empty() {
                std::ptr::copy_nonoverlapping(
                    file_wide.as_ptr(),
                    base_byte_ptr.add(struct_size + name_len_bytes) as *mut u16,
                    file_wide.len(),
                );
            }
        }

        Self { buffer }
    }

    /// Allocates and initializes an aligned `EVENT_TRACE_PROPERTIES_V2` buffer, optionally embedding
    /// a 256-bit [`PerfGroupMask`] (`ETW_EXT_ENABLE_FLAGS`) extension item for System Logger sessions.
    pub fn new_v2(
        session_name: &str,
        properties: &EventTraceProperties,
        session_guid: GUID,
        group_mask: Option<&PerfGroupMask>,
    ) -> Self {
        let name_wide: Vec<u16> = session_name.encode_utf16().chain(Some(0)).collect();
        let file_wide: Vec<u16> = properties
            .log_file_name
            .as_ref()
            .map(|s| s.encode_utf16().chain(Some(0)).collect())
            .unwrap_or_default();

        let struct_size = size_of::<EVENT_TRACE_PROPERTIES_V2>();
        let name_len_bytes = (name_wide.len() * size_of::<u16>()).next_multiple_of(8);
        let file_len_bytes = (file_wide.len() * size_of::<u16>()).next_multiple_of(8);

        // V2 extension item for PerfGroupMask: 4-byte header (ExtType: u16, ExtSize: u16) + 32-byte PerfGroupMask = 36 bytes (padded to 40 for 8-byte alignment)
        let has_ext_mask = group_mask.is_some_and(|m| m.has_extended_flags());
        let ext_len_bytes = if has_ext_mask { 40 } else { 0 };

        let total_size = struct_size + name_len_bytes + file_len_bytes + ext_len_bytes;
        let u64_len = total_size.div_ceil(size_of::<u64>());
        let mut buffer = vec![0u64; u64_len];
        let base_byte_ptr = buffer.as_mut_ptr() as *mut u8;
        let props_ptr = base_byte_ptr as *mut EVENT_TRACE_PROPERTIES_V2;

        // SAFETY: `buffer` is 8-byte aligned and sized to contain the V2 struct, strings, and extension block.
        unsafe {
            (*props_ptr).Wnode.BufferSize = (u64_len * size_of::<u64>()) as u32;
            (*props_ptr).Wnode.Flags = WNODE_FLAG_TRACED_GUID | WNODE_FLAG_VERSIONED_PROPERTIES;
            (*props_ptr).Wnode.ClientContext = 1; // QPC timestamp
            (*props_ptr).Wnode.Guid = session_guid;
            (*props_ptr).Anonymous2.V2Control = 2;

            let mut log_mode = properties.log_file_mode;
            if log_mode == 0 && file_wide.is_empty() {
                log_mode = EVENT_TRACE_REAL_TIME_MODE;
            }

            (*props_ptr).LogFileMode = log_mode;
            (*props_ptr).BufferSize = properties.buffer_size;
            (*props_ptr).MinimumBuffers = properties.minimum_buffers;
            (*props_ptr).MaximumBuffers = properties.maximum_buffers;
            (*props_ptr).FlushTimer = properties.flush_timer;
            (*props_ptr).EnableFlags = group_mask.map_or(0, |m| m.legacy_enable_flags());
            (*props_ptr).LoggerNameOffset = struct_size as u32;

            std::ptr::copy_nonoverlapping(
                name_wide.as_ptr(),
                base_byte_ptr.add(struct_size) as *mut u16,
                name_wide.len(),
            );

            if !file_wide.is_empty() {
                let file_offset = struct_size + name_len_bytes;
                (*props_ptr).LogFileNameOffset = file_offset as u32;
                std::ptr::copy_nonoverlapping(
                    file_wide.as_ptr(),
                    base_byte_ptr.add(file_offset) as *mut u16,
                    file_wide.len(),
                );
            }

            if let Some(mask) = group_mask
                && has_ext_mask
            {
                let ext_offset = struct_size + name_len_bytes + file_len_bytes;
                let ext_ptr = base_byte_ptr.add(ext_offset);
                let item_size: u16 = (4 + size_of::<PerfGroupMask>()) as u16;
                std::ptr::copy_nonoverlapping(
                    &ETW_EXT_ENABLE_FLAGS as *const u16 as *const u8,
                    ext_ptr,
                    2,
                );
                std::ptr::copy_nonoverlapping(&item_size as *const u16 as *const u8, ext_ptr.add(2), 2);
                std::ptr::copy_nonoverlapping(
                    mask.masks.as_ptr() as *const u8,
                    ext_ptr.add(4),
                    size_of::<PerfGroupMask>(),
                );
            }
        }

        Self { buffer }
    }

    /// Extracts kernel buffer and event drop statistics from the underlying `EVENT_TRACE_PROPERTIES` header.
    #[inline]
    pub fn statistics(&self) -> TraceStatistics {
        // SAFETY: `self.buffer` always starts with a valid `EVENT_TRACE_PROPERTIES` header.
        let props = unsafe { &*self.as_ptr() };
        TraceStatistics {
            number_of_buffers: props.NumberOfBuffers,
            free_buffers: props.FreeBuffers,
            events_lost: props.EventsLost,
            buffers_written: props.BuffersWritten,
            log_buffers_lost: props.LogBuffersLost,
            real_time_buffers_lost: props.RealTimeBuffersLost,
        }
    }

    /// Provides a raw mutable pointer to the encapsulated `EVENT_TRACE_PROPERTIES` header.
    #[inline]
    pub fn as_mut_ptr(&mut self) -> *mut EVENT_TRACE_PROPERTIES {
        self.buffer.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES
    }

    /// Provides a raw immutable pointer to the encapsulated `EVENT_TRACE_PROPERTIES` header.
    #[inline]
    pub fn as_ptr(&self) -> *const EVENT_TRACE_PROPERTIES {
        self.buffer.as_ptr() as *const EVENT_TRACE_PROPERTIES
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sensors::etw::masks::KernelFlag;

    /// Validates that TracePropertiesBuffer correctly computes buffer sizes, offsets,
    /// and preserves UTF-16 wide character null-terminated strings.
    #[test]
    fn test_trace_properties_buffer_layout_and_offsets() {
        let props = EventTraceProperties {
            buffer_size: 512,
            minimum_buffers: 8,
            maximum_buffers: 16,
            maximum_file_size: 0,
            log_file_mode: EVENT_TRACE_REAL_TIME_MODE,
            flush_timer: 1,
            log_file_name: Some("test.etl".to_string()),
        };

        let session_name = "MyTestSession";
        let guid = GUID {
            data1: 0x1234_5678,
            data2: 0x9ABC,
            data3: 0xDEF0,
            data4: [1, 2, 3, 4, 5, 6, 7, 8],
        };

        let mut buf = TracePropertiesBuffer::new(session_name, &props, guid, 0x0000_0001);
        let ptr = buf.as_mut_ptr();

        unsafe {
            assert_eq!((*ptr).BufferSize, 512);
            assert_eq!((*ptr).MinimumBuffers, 8);
            assert_eq!((*ptr).MaximumBuffers, 16);
            assert_eq!((*ptr).FlushTimer, 1);
            assert_eq!((*ptr).EnableFlags, 0x0000_0001);
            assert_eq!((*ptr).Wnode.Guid.data1, 0x1234_5678);

            let struct_size = size_of::<EVENT_TRACE_PROPERTIES>() as u32;
            assert_eq!((*ptr).LoggerNameOffset, struct_size);

            let name_len_bytes = (session_name.encode_utf16().count() + 1) * size_of::<u16>();
            assert_eq!(
                (*ptr).LogFileNameOffset,
                struct_size + name_len_bytes as u32
            );

            let name_ptr = (ptr as *const u8).add((*ptr).LoggerNameOffset as usize) as *const u16;
            let mut name_u16 = Vec::new();
            let mut i = 0;
            while *name_ptr.add(i) != 0 {
                name_u16.push(*name_ptr.add(i));
                i += 1;
            }
            assert_eq!(String::from_utf16_lossy(&name_u16), session_name);
        }
    }

    #[test]
    fn test_trace_properties_v2_with_perf_group_mask() {
        let props = EventTraceProperties {
            buffer_size: 1024,
            minimum_buffers: 64,
            maximum_buffers: 128,
            maximum_file_size: 0,
            log_file_mode: EVENT_TRACE_REAL_TIME_MODE,
            flush_timer: 1,
            log_file_name: None,
        };
        let mask = PerfGroupMask::from_flag(KernelFlag::Process)
            | KernelFlag::SystemCall
            | KernelFlag::ObHandle;
        let guid = GUID {
            data1: 0xAA,
            data2: 0,
            data3: 0,
            data4: [0; 8],
        };

        let buf = TracePropertiesBuffer::new_v2("Pulsar-Kernel-Logger", &props, guid, Some(&mask));
        let v2_ptr = buf.as_ptr() as *const EVENT_TRACE_PROPERTIES_V2;
        unsafe {
            assert_eq!(
                (*v2_ptr).Wnode.Flags,
                WNODE_FLAG_TRACED_GUID | WNODE_FLAG_VERSIONED_PROPERTIES
            );
            assert_eq!((*v2_ptr).Anonymous2.V2Control, 2);
            assert_eq!((*v2_ptr).BufferSize, 1024);
        }
        assert!(!buf.statistics().has_drops());
    }
}
