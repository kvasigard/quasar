//! Per-CPU shared memory ring buffer IOCTL definitions and message contracts.
//!
//! Provides the control codes and payload structures required to:
//! 1. Project the contiguous per-CPU shared data and status memory pools into user space.
//! 2. Register a user-mode Win32 notification event with the kernel.

use crate::ctl_code;
use super::{IoctlMessage, FILE_ANY_ACCESS, METHOD_BUFFERED, SINGULARITY_DEVICE_TYPE};

/// Custom Function Code for per-CPU ring buffer memory mapping (>= 2048 / 0x800).
pub const FUNCTION_MAP_PER_CPU_BUFFER: u32 = 0x802;

/// Custom Function Code for registering a user-mode Win32 notification event handle.
pub const FUNCTION_REGISTER_EVENT: u32 = 0x803;

/// IOCTL control code instructing the driver to project per-CPU buffers into the calling process.
pub const IOCTL_MAP_PER_CPU_BUFFER: u32 = ctl_code!(
    SINGULARITY_DEVICE_TYPE,
    FUNCTION_MAP_PER_CPU_BUFFER,
    METHOD_BUFFERED,
    FILE_ANY_ACCESS
);

/// IOCTL control code instructing the driver to register a Win32 event for kernel notification.
pub const IOCTL_REGISTER_EVENT: u32 = ctl_code!(
    SINGULARITY_DEVICE_TYPE,
    FUNCTION_REGISTER_EVENT,
    METHOD_BUFFERED,
    FILE_ANY_ACCESS
);

/// Request payload to map the per-CPU shared ring buffers.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MapPerCpuBuffer;

/// Response payload containing mapped user-mode virtual addresses and per-CPU geometry.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PerCpuMapResponse {
    /// Base address of the contiguous data buffer mapped into user space (Read-Only).
    pub data_address: u64,
    /// Base address of the contiguous status buffer mapped into user space (Read-Write).
    pub status_address: u64,
    /// Number of active logical CPU cores allocated.
    pub cpu_count: u32,
    /// Size in bytes of each core's data section partition.
    pub per_cpu_data_size: u32,
    /// Size in bytes of each core's status header structure (including 64-byte padding).
    pub per_cpu_status_size: u32,
    /// Explicit padding to ensure 8-byte alignment of the response payload.
    pub _reserved: u32,
}

/// Request structure sent by user-mode to register a notification event handle.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegisterEventRequest {
    /// Win32 Event handle (passed as u64 for 64-bit ABI stability across architectures).
    pub event_handle: u64,
}

impl IoctlMessage for MapPerCpuBuffer {
    const CODE: u32 = IOCTL_MAP_PER_CPU_BUFFER;
    type Response = PerCpuMapResponse;
}

impl IoctlMessage for RegisterEventRequest {
    const CODE: u32 = IOCTL_REGISTER_EVENT;
    type Response = ();
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::{align_of, offset_of, size_of};

    #[test]
    fn test_per_cpu_map_response_layout() {
        assert_eq!(size_of::<PerCpuMapResponse>(), 32);
        assert_eq!(align_of::<PerCpuMapResponse>(), 8);
        assert_eq!(offset_of!(PerCpuMapResponse, data_address), 0);
        assert_eq!(offset_of!(PerCpuMapResponse, status_address), 8);
        assert_eq!(offset_of!(PerCpuMapResponse, cpu_count), 16);
        assert_eq!(offset_of!(PerCpuMapResponse, per_cpu_data_size), 20);
        assert_eq!(offset_of!(PerCpuMapResponse, per_cpu_status_size), 24);
        assert_eq!(offset_of!(PerCpuMapResponse, _reserved), 28);
    }

    #[test]
    fn test_register_event_request_layout() {
        assert_eq!(size_of::<RegisterEventRequest>(), 8);
        assert_eq!(align_of::<RegisterEventRequest>(), 8);
        assert_eq!(offset_of!(RegisterEventRequest, event_handle), 0);
    }
}
