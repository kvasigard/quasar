//! Domain event payloads for shared memory ring buffer telemetry.

use super::contract::TemplateEvent;
use super::types::DriverEventType;

/// Telemetry payload emitted prior to a process or thread handle creation or duplication operation.
///
/// Captured by the Singularity driver's Object Manager pre-operation callbacks (`OB_OPERATION_HANDLE_CREATE`
/// and `OB_OPERATION_HANDLE_DUPLICATE`).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandlePreOpEvent {
    /// Process identifier of the caller requesting handle access.
    pub source_pid: u32,
    /// Process identifier of the target process whose handle is being created/duplicated.
    pub target_pid: u32,
    /// Desired access mask requested by the source process.
    pub desired_access: u32,
    /// Operation discriminator (1 = Creation, 2 = Duplication).
    pub operation: u8,
    /// Truncated short image name of the source process (null-terminated if under 16 bytes).
    pub short_name: [u8; 16],
}

impl HandlePreOpEvent {
    /// Creates a new `HandlePreOpEvent` payload.
    ///
    /// Copies up to 15 bytes of `source_short_name` into the 16-byte fixed buffer,
    /// ensuring remaining bytes are zeroed for null termination.
    ///
    /// # Arguments
    ///
    /// * `source_pid` - PID of the process requesting access.
    /// * `target_pid` - PID of the target process whose handle is being created/duplicated.
    /// * `desired_access` - Mask of requested access rights.
    /// * `operation` - Handle operation type (`1` = Create, `2` = Duplicate).
    /// * `source_short_name` - Truncated short image name of the source process.
    pub fn new(
        source_pid: u32,
        target_pid: u32,
        desired_access: u32,
        operation: u8,
        source_short_name: &[u8],
    ) -> Self {
        let mut short_name = [0u8; 16];
        let copy_len = source_short_name.len().min(15);
        short_name[..copy_len].copy_from_slice(&source_short_name[..copy_len]);

        Self {
            source_pid,
            target_pid,
            desired_access,
            operation,
            short_name,
        }
    }
}

impl TemplateEvent for HandlePreOpEvent {
    const EVENT_TYPE: DriverEventType = DriverEventType::HandlePreOperation;
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::contract::DriverEvent;
    use core::mem::{align_of, offset_of, size_of};

    #[test]
    fn test_handle_pre_op_event_layout() {
        assert_eq!(size_of::<HandlePreOpEvent>(), 32);
        assert_eq!(align_of::<HandlePreOpEvent>(), 4);
        assert_eq!(offset_of!(HandlePreOpEvent, source_pid), 0);
        assert_eq!(offset_of!(HandlePreOpEvent, target_pid), 4);
        assert_eq!(offset_of!(HandlePreOpEvent, desired_access), 8);
        assert_eq!(offset_of!(HandlePreOpEvent, operation), 12);
        assert_eq!(offset_of!(HandlePreOpEvent, short_name), 13);
    }

    #[test]
    fn test_handle_pre_op_event_contract() {
        let mut short_name = [0u8; 16];
        short_name[..5].copy_from_slice(b"lsass");

        let event = HandlePreOpEvent {
            source_pid: 1000,
            target_pid: 4,
            desired_access: 0x1FFFFF,
            operation: 1,
            short_name,
        };

        // Verify DriverEvent metadata via blanket implementation
        assert_eq!(event.event_type(), DriverEventType::HandlePreOperation);
        assert_eq!(event.payload_len(), 32);

        // Verify zero-copy write_payload serialization
        let mut buffer = [0u8; 32];
        // SAFETY: Buffer length matches payload_len() exactly.
        unsafe {
            event.write_payload(buffer.as_mut_ptr());
        }

        let reconstructed = unsafe { core::ptr::read_unaligned(buffer.as_ptr() as *const HandlePreOpEvent) };
        assert_eq!(event, reconstructed);
    }
}
