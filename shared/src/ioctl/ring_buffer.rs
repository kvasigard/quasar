//! Shared memory ring buffer initialization IOCTL definitions and payload structures.

use crate::ctl_code;
use super::{IoctlMessage, FILE_ANY_ACCESS, METHOD_BUFFERED, SINGULARITY_DEVICE_TYPE};

/// Custom Function Code for ring buffer initialization (>= 2048 / 0x800).
pub const FUNCTION_INIT_RING: u32 = 0x802;

/// IOCTL control code instructing the driver to initialize the shared memory ring buffer.
pub const IOCTL_INIT_RING_BUFFER: u32 = ctl_code!(
    SINGULARITY_DEVICE_TYPE,
    FUNCTION_INIT_RING,
    METHOD_BUFFERED,
    FILE_ANY_ACCESS
);

/// Request payload to initialize the shared memory ring buffer.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InitRingBuffer {
    /// User-mode Win32 Event handle (passed as u64 for 64-bit ABI stability).
    pub event_handle: u64,
}

/// Response payload containing mapped user-mode virtual addresses and capacities.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InitRingBufferResponse {
    /// User-mode mapped base address of the 4 MB data buffer (PAGE_READONLY).
    pub data_buffer_ptr: u64,
    /// Size of the data buffer in bytes.
    pub data_buffer_size: u32,
    /// Explicit padding to align status_page_ptr to 8 bytes.
    pub _reserved1: u32,
    /// User-mode mapped base address of the 4 KB consumer status page (PAGE_READWRITE).
    pub status_page_ptr: u64,
    /// Size of the status page in bytes.
    pub status_page_size: u32,
    /// Explicit tail padding to align struct size to 8 bytes.
    pub _reserved2: u32,
}

impl IoctlMessage for InitRingBuffer {
    const CODE: u32 = IOCTL_INIT_RING_BUFFER;
    type Response = InitRingBufferResponse;
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::{align_of, offset_of, size_of};

    #[test]
    fn test_init_ring_buffer_layout() {
        assert_eq!(size_of::<InitRingBuffer>(), 8);
        assert_eq!(align_of::<InitRingBuffer>(), 8);
        assert_eq!(offset_of!(InitRingBuffer, event_handle), 0);
    }

    #[test]
    fn test_init_ring_buffer_response_layout() {
        assert_eq!(size_of::<InitRingBufferResponse>(), 32);
        assert_eq!(align_of::<InitRingBufferResponse>(), 8);
        assert_eq!(offset_of!(InitRingBufferResponse, data_buffer_ptr), 0);
        assert_eq!(offset_of!(InitRingBufferResponse, data_buffer_size), 8);
        assert_eq!(offset_of!(InitRingBufferResponse, _reserved1), 12);
        assert_eq!(offset_of!(InitRingBufferResponse, status_page_ptr), 16);
        assert_eq!(offset_of!(InitRingBufferResponse, status_page_size), 24);
        assert_eq!(offset_of!(InitRingBufferResponse, _reserved2), 28);
    }
}
