//! Trait-based event contracts for shared memory ring buffer transport.
//!
//! Provides the core abstraction for serializing driver telemetry events into the ring buffer
//! without intermediate heap allocations or manual raw byte casting.
//!
//! # Architecture & Adding New Events
//!
//! All event payloads emitted to the ring buffer implement the [`DriverEvent`] trait.
//! There are two categories of events:
//!
//! ## 1. Fixed-Size Template Events (Recommended for Most Telemetry)
//! Most kernel telemetry events (handles, process tokens, threads) are fixed-size, C-compatible
//! structures. These should implement the [`TemplateEvent`] marker trait:
//!
//! ```rust,ignore
//! #[repr(C)]
//! #[derive(Debug, Clone, Copy, PartialEq, Eq)]
//! pub struct ProcessCreateEvent {
//!     pub parent_pid: u32,
//!     pub child_pid: u32,
//!     pub image_path: [u8; 260],
//! }
//!
//! impl TemplateEvent for ProcessCreateEvent {
//!     const EVENT_TYPE: DriverEventType = DriverEventType::ProcessCreate;
//! }
//! ```
//!
//! Any type implementing [`TemplateEvent`] automatically inherits an optimized, zero-copy
//! blanket implementation of [`DriverEvent`].
//!
//! ## 2. Variable-Size Dynamic Events (For Dynamic Payloads)
//! For events with variable-length payloads (such as arbitrary-length command lines, registry paths,
//! or file streams), implement [`DriverEvent`] directly:
//!
//! ```rust,ignore
//! pub struct DynamicPathEvent<'a> {
//!     pub pid: u32,
//!     pub path: &'a [u8],
//! }
//!
//! impl<'a> DriverEvent for DynamicPathEvent<'a> {
//!     fn event_type(&self) -> DriverEventType {
//!         DriverEventType::FilePath
//!     }
//!
//!     fn payload_len(&self) -> usize {
//!         core::mem::size_of::<u32>() + self.path.len()
//!     }
//!
//!     unsafe fn write_payload(&self, dest: *mut u8) {
//!         unsafe {
//!             core::ptr::copy_nonoverlapping(
//!                 &self.pid as *const u32 as *const u8,
//!                 dest,
//!                 core::mem::size_of::<u32>(),
//!             );
//!             core::ptr::copy_nonoverlapping(
//!                 self.path.as_ptr(),
//!                 dest.add(core::mem::size_of::<u32>()),
//!                 self.path.len(),
//!             );
//!         }
//!     }
//! }
//! ```

use super::types::DriverEventType;

/// Core serialization contract for driver events written to the shared memory ring buffer.
///
/// Enables the kernel producer to query payload dimensions, assign record header metadata,
/// and serialize payload bytes directly into reserved ring buffer memory slots.
pub trait DriverEvent {
    /// Returns the discriminator identifying this event type in the transport record header.
    fn event_type(&self) -> DriverEventType;

    /// Returns the size in bytes of the event payload (excluding the 32-byte [`RecordHeader`]).
    fn payload_len(&self) -> usize;

    /// Serializes the event payload directly into the reserved ring buffer destination pointer.
    ///
    /// # Arguments
    ///
    /// * `dest` - Pointer to the start of the payload region inside the claimed slot.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `dest` points to a contiguous, valid, writable memory region
    /// of at least [`Self::payload_len`] bytes.
    unsafe fn write_payload(&self, dest: *mut u8);
}

/// Marker trait for fixed-size, C-compatible telemetry event templates.
///
/// Types implementing this trait must be `Copy` and follow a fixed memory layout.
/// Implementing this trait automatically provides a zero-copy blanket implementation of
/// [`DriverEvent`].
pub trait TemplateEvent: Copy {
    /// The discriminator identifying this specific event type in the transport record header.
    const EVENT_TYPE: DriverEventType;
}

// Blanket implementation: Any TemplateEvent automatically implements DriverEvent.
impl<T: TemplateEvent> DriverEvent for T {
    #[inline(always)]
    fn event_type(&self) -> DriverEventType {
        T::EVENT_TYPE
    }

    #[inline(always)]
    fn payload_len(&self) -> usize {
        core::mem::size_of::<T>()
    }

    #[inline(always)]
    unsafe fn write_payload(&self, dest: *mut u8) {
        // SAFETY:
        // The caller guarantees that `dest` points to at least `payload_len()` writable bytes.
        // Because `T` implements `TemplateEvent` (which requires `Copy`), copying `size_of::<T>()`
        // contiguous bytes from `self` into `dest` produces a valid bitwise representation with
        // zero intermediate heap allocations.
        unsafe {
            core::ptr::copy_nonoverlapping(
                self as *const T as *const u8,
                dest,
                core::mem::size_of::<T>(),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct MockFixedEvent {
        value_a: u32,
        value_b: u64,
    }

    impl TemplateEvent for MockFixedEvent {
        const EVENT_TYPE: DriverEventType = DriverEventType::HandlePreOperation;
    }

    #[test]
    fn test_template_event_blanket_implementation() {
        let event = MockFixedEvent {
            value_a: 0x1234_5678,
            value_b: 0x9ABC_DEF0_1234_5678,
        };

        assert_eq!(event.event_type(), DriverEventType::HandlePreOperation);
        assert_eq!(event.payload_len(), core::mem::size_of::<MockFixedEvent>());

        let mut buffer = [0u8; core::mem::size_of::<MockFixedEvent>()];
        // SAFETY: `buffer` has exact size of `MockFixedEvent`.
        unsafe {
            event.write_payload(buffer.as_mut_ptr());
        }

        let reconstructed = unsafe { core::ptr::read_unaligned(buffer.as_ptr() as *const MockFixedEvent) };
        assert_eq!(event, reconstructed);
    }
}
