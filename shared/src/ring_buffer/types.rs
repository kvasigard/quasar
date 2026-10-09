//! Shared memory ring buffer transport primitives and wire formats.
//!
//! Defines the partitioned per-CPU ring buffer headers, cache-line alignment guarantees,
//! event header wire formats, and event type discriminators.

use core::sync::atomic::AtomicU32;

/// Default data partition size per logical CPU core (512 KB).
pub const PER_CPU_DATA_SIZE: usize = 512 * 1024;

/// Unique 16-bit magic identifier for event records (0x5153 = 'QS' for Quasar).
pub const EVENT_MAGIC: u16 = 0x5153;

/// Sentinel event type indicating circular buffer wrap-around.
///
/// When the producer cannot fit an event at the tail of the buffer and wraps to offset 0,
/// this header is written into the remaining slack bytes so the consumer knows to reset its
/// read cursor to 0 without attempting to parse trailing padding.
// Sentinel event type indicating circular buffer wrap-around.
pub const EVENT_TYPE_WRAP: u16 = 0xFFFF;

/// Status header for an individual core's SPSC ring buffer.
///
/// Enforces 64-byte hardware cache line isolation to eliminate false sharing between cores.
/// `write_cursor`, `read_cursor`, and `dropped_events` each reside on separate 64-byte cache lines.
#[repr(C)]
#[repr(align(64))]
pub struct PerCpuRingHeader {
    /// Monotonic write byte offset maintained exclusively by kernel core producer.
    pub write_cursor: AtomicU32,
    _pad1: [u8; 60],
    /// Monotonic read byte offset updated exclusively by user-mode consumer.
    pub read_cursor: AtomicU32,
    _pad2: [u8; 60],
    /// Counter of events dropped due to buffer capacity exhaustion on this core.
    pub dropped_events: AtomicU32,
    _pad3: [u8; 60],
}

// Compile-time layout guarantees
const _: () = assert!(core::mem::size_of::<PerCpuRingHeader>() == 192);
const _: () = assert!(core::mem::align_of::<PerCpuRingHeader>() == 64);

/// Wire header preceding every serialized telemetry event record.
///
/// Stamped with sub-microsecond hardware timestamp (`KeQueryPerformanceCounter`) and the
/// executing CPU core identifier.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventHeader {
    /// Validation magic number ([`EVENT_MAGIC`]).
    pub magic: u16,
    /// Telemetry event type discriminator ([`DriverEventType`]).
    pub event_type: u16,
    /// Size of the payload immediately following this header in bytes.
    pub payload_len: u32,
    /// Monotonic hardware performance counter timestamp (QPC ticks).
    pub timestamp: u64,
    /// Logical processor index that emitted this event.
    pub cpu_id: u32,
    /// Reserved for 8-byte alignment; zero-initialized.
    pub _reserved: u32,
}

// Compile-time layout guarantees: 24 bytes, 8-byte aligned, zero implicit padding
const _: () = assert!(core::mem::size_of::<EventHeader>() == 24);
const _: () = assert!(core::mem::align_of::<EventHeader>() == 8);

/// Discriminator identifying the telemetry event variant in the wire [`EventHeader`].
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriverEventType {
    /// Pre-operation handle creation or duplication targeting `lsass.exe`.
    LsassAccess = 0x0001,
}

impl TryFrom<u16> for DriverEventType {
    type Error = ();

    #[inline]
    fn try_from(val: u16) -> Result<Self, Self::Error> {
        match val {
            0x0001 => Ok(Self::LsassAccess),
            _ => Err(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::{align_of, offset_of, size_of};

    #[test]
    fn test_per_cpu_ring_header_layout() {
        assert_eq!(size_of::<PerCpuRingHeader>(), 192);
        assert_eq!(align_of::<PerCpuRingHeader>(), 64);
        assert_eq!(offset_of!(PerCpuRingHeader, write_cursor), 0);
        assert_eq!(offset_of!(PerCpuRingHeader, read_cursor), 64);
        assert_eq!(offset_of!(PerCpuRingHeader, dropped_events), 128);
    }

    #[test]
    fn test_event_header_layout() {
        assert_eq!(size_of::<EventHeader>(), 24);
        assert_eq!(align_of::<EventHeader>(), 8);
        assert_eq!(offset_of!(EventHeader, magic), 0);
        assert_eq!(offset_of!(EventHeader, event_type), 2);
        assert_eq!(offset_of!(EventHeader, payload_len), 4);
        assert_eq!(offset_of!(EventHeader, timestamp), 8);
        assert_eq!(offset_of!(EventHeader, cpu_id), 16);
        assert_eq!(offset_of!(EventHeader, _reserved), 20);
    }

    #[test]
    fn test_driver_event_type_try_from() {
        assert_eq!(
            DriverEventType::try_from(0x0001),
            Ok(DriverEventType::LsassAccess)
        );
        assert_eq!(DriverEventType::try_from(0x9999), Err(()));
    }
}
