//! Telemetry payload definitions for LSASS handle operations.

use crate::ring_buffer::contract::TemplateEvent;
use crate::ring_buffer::types::DriverEventType;

/// Telemetry payload emitted prior to an `lsass.exe` process handle creation or duplication operation.
///
/// Captured by the Singularity driver's Object Manager pre-operation callbacks (`OB_OPERATION_HANDLE_CREATE`
/// and `OB_OPERATION_HANDLE_DUPLICATE`) targeting `lsass.exe` when sensitive access rights are requested.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LsassAccessEvent {
    /// Process identifier of the caller requesting handle access.
    pub source_pid: u32,
    /// Process identifier of the authentic LSASS process.
    pub target_pid: u32,
    /// Desired access mask originally requested by the source process.
    pub desired_access: u32,
    /// Granted access mask after kernel driver in-flight mitigation stripping.
    pub granted_access: u32,
    /// Token integrity RID of the caller (e.g. 0x2000 Medium, 0x3000 High, 0x4000 System).
    pub integrity_level: u32,
    /// Kernel code-signing level (`SeSigningLevel`, e.g. 0x01 Unsigned, 0x08 Microsoft, 0x0C Windows).
    pub signature_level: u8,
    /// Kernel process protection byte (`PsProtection`, packed type and signer).
    pub protection: u8,
    /// Operation discriminator (1 = Creation, 2 = Duplication).
    pub operation: u8,
    /// Reserved byte for 4-byte/8-byte field alignment; zero-initialized.
    pub _reserved: u8,
    /// Truncated short image name of the source process (null-terminated if under 16 bytes).
    pub short_name: [u8; 16],
}

/// Backwards-compatible alias for [`LsassAccessEvent`].
pub type ProcessHandlePreOpEvent = LsassAccessEvent;
/// Backwards-compatible alias for [`LsassAccessEvent`].
pub type HandlePreOpEvent = LsassAccessEvent;

impl LsassAccessEvent {
    /// Creates a new `LsassAccessEvent` payload.
    ///
    /// Copies up to 15 bytes of `source_short_name` into the 16-byte fixed buffer,
    /// ensuring remaining bytes are zeroed for null termination.
    ///
    /// # Arguments
    ///
    /// * `source_pid` - PID of the process requesting access.
    /// * `target_pid` - PID of the target process whose handle is being created/duplicated.
    /// * `desired_access` - Mask of requested access rights.
    /// * `granted_access` - Mask of granted access rights post-mitigation.
    /// * `integrity_level` - Token integrity RID.
    /// * `signature_level` - Kernel code-signing level byte.
    /// * `protection` - Kernel process protection byte.
    /// * `operation` - Handle operation type (`1` = Create, `2` = Duplicate).
    /// * `source_short_name` - Truncated short image name of the source process.
    ///
    /// # Return values
    ///
    /// * `LsassAccessEvent` - The newly constructed event payload.
    pub fn new(
        source_pid: u32,
        target_pid: u32,
        desired_access: u32,
        granted_access: u32,
        integrity_level: u32,
        signature_level: u8,
        protection: u8,
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
            granted_access,
            integrity_level,
            signature_level,
            protection,
            operation,
            _reserved: 0,
            short_name,
        }
    }
}

impl TemplateEvent for LsassAccessEvent {
    const EVENT_TYPE: DriverEventType = DriverEventType::LsassAccess;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ring_buffer::contract::DriverEvent;
    use crate::ring_buffer::types::EventHeader;
    use core::mem::{align_of, offset_of, size_of};

    #[test]
    fn test_lsass_access_event_layout() {
        assert_eq!(size_of::<LsassAccessEvent>(), 40);
        assert_eq!(align_of::<LsassAccessEvent>(), 4);
        assert_eq!(offset_of!(LsassAccessEvent, source_pid), 0);
        assert_eq!(offset_of!(LsassAccessEvent, target_pid), 4);
        assert_eq!(offset_of!(LsassAccessEvent, desired_access), 8);
        assert_eq!(offset_of!(LsassAccessEvent, granted_access), 12);
        assert_eq!(offset_of!(LsassAccessEvent, integrity_level), 16);
        assert_eq!(offset_of!(LsassAccessEvent, signature_level), 20);
        assert_eq!(offset_of!(LsassAccessEvent, protection), 21);
        assert_eq!(offset_of!(LsassAccessEvent, operation), 22);
        assert_eq!(offset_of!(LsassAccessEvent, _reserved), 23);
        assert_eq!(offset_of!(LsassAccessEvent, short_name), 24);

        // Verify that Header (24 bytes) + Payload (40 bytes) aligns to a single 64-byte cache line
        assert_eq!(size_of::<EventHeader>() + size_of::<LsassAccessEvent>(), 64);
    }

    #[test]
    fn test_lsass_access_event_contract() {
        let mut short_name = [0u8; 16];
        short_name[..5].copy_from_slice(b"mimik");

        let event = LsassAccessEvent {
            source_pid: 1000,
            target_pid: 816,
            desired_access: 0x1FFFFF,
            granted_access: 0x1000,
            integrity_level: 0x3000,
            signature_level: 0x01,
            protection: 0x00,
            operation: 1,
            _reserved: 0,
            short_name,
        };

        // Verify DriverEvent metadata via blanket implementation
        assert_eq!(event.event_type(), DriverEventType::LsassAccess);
        assert_eq!(event.payload_len(), 40);

        // Verify zero-copy write_payload serialization
        let mut buffer = [0u8; 40];
        // SAFETY: Buffer length matches payload_len() exactly.
        unsafe {
            event.write_payload(buffer.as_mut_ptr());
        }

        let reconstructed =
            unsafe { core::ptr::read_unaligned(buffer.as_ptr() as *const LsassAccessEvent) };
        assert_eq!(event, reconstructed);
    }
}
