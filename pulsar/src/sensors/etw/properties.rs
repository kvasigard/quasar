//! Safe RAII memory management for Win32 `EVENT_TRACE_PROPERTIES` and trailing strings.

use std::mem::size_of;
use windows_sys::core::GUID;
use windows_sys::Win32::System::Diagnostics::Etw::{
    EVENT_TRACE_PROPERTIES, EVENT_TRACE_REAL_TIME_MODE, WNODE_FLAG_TRACED_GUID,
};

use super::session::EventTraceProperties;

/// RAII memory manager for Win32 `EVENT_TRACE_PROPERTIES`.
///
/// Windows requires `EVENT_TRACE_PROPERTIES` and its trailing UTF-16 strings (LoggerName, LogFileName)
/// to reside in a single contiguous, aligned block of memory. This struct encapsulates the byte allocation,
/// string copies, and offset calculations safely without exposing raw pointer manipulation to callers.
pub struct TracePropertiesBuffer {
    buffer: Vec<u8>,
}

impl TracePropertiesBuffer {
    /// Allocates and initializes an aligned `EVENT_TRACE_PROPERTIES` buffer with trailing UTF-16 strings.
    ///
    /// # Arguments
    ///
    /// * `session_name` - The unique name of the ETW session.
    /// * `properties` - User-configured buffer and flush parameters.
    /// * `session_guid` - The session GUID (`SystemTraceControlGuid` for kernel, or `GUID_NULL` for user).
    /// * `enable_flags` - Kernel flag bitmask (for NT Kernel Logger, or `0` for user sessions).
    ///
    /// # Returns
    ///
    /// An initialized, properly aligned `TracePropertiesBuffer`.
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
        let mut buffer = vec![0u8; total_size];
        let props_ptr = buffer.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;

        // SAFETY: The buffer is allocated with `total_size` bytes, which strictly covers
        // `EVENT_TRACE_PROPERTIES` plus both null-terminated wide strings without overlapping.
        unsafe {
            (*props_ptr).Wnode.BufferSize = total_size as u32;
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
                buffer.as_mut_ptr().add(struct_size) as *mut u16,
                name_wide.len(),
            );

            if !file_wide.is_empty() {
                std::ptr::copy_nonoverlapping(
                    file_wide.as_ptr(),
                    buffer.as_mut_ptr().add(struct_size + name_len_bytes) as *mut u16,
                    file_wide.len(),
                );
            }
        }

        Self { buffer }
    }

    /// Provides a raw mutable pointer to the encapsulated `EVENT_TRACE_PROPERTIES` header.
    ///
    /// # Safety
    ///
    /// The caller must ensure the pointer is passed only to valid Win32 APIs expecting
    /// a contiguous `EVENT_TRACE_PROPERTIES` buffer.
    pub fn as_mut_ptr(&mut self) -> *mut EVENT_TRACE_PROPERTIES {
        self.buffer.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES
    }

    /// Provides a raw immutable pointer to the encapsulated `EVENT_TRACE_PROPERTIES` header.
    pub fn as_ptr(&self) -> *const EVENT_TRACE_PROPERTIES {
        self.buffer.as_ptr() as *const EVENT_TRACE_PROPERTIES
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
            assert_eq!((*ptr).LogFileNameOffset, struct_size + name_len_bytes as u32);

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
}
