//! Lock-free, zero-spin event queue writing algorithms for per-CPU partitions.
//!
//! Provides the core single-producer commit logic for writing telemetry events directly
//! into per-CPU circular memory partitions without locks, CAS loops, or cross-core contention.

use core::ptr::NonNull;
use core::sync::atomic::Ordering;

use shared::ring_buffer::{
    DriverEvent, EVENT_MAGIC, EVENT_TYPE_WRAP, EventHeader, PER_CPU_DATA_SIZE, PerCpuRingHeader,
};

use super::error::RingBufferError;
use crate::foundation::irql::DispatchIrqlGuard;

/// The permanent physical Per-CPU ring buffer backing store.
///
/// Owns the underlying NonPaged kernel pool allocations for the entire lifetime of the driver.
/// Decoupling the physical backing memory from client user-mode sessions ensures that the kernel
/// can continue recording telemetry even when no user-mode agent is currently attached.
pub struct PerCpuRingBuffer {
    pub(crate) cpu_count: u32,
    pub(crate) total_data_size: usize,
    pub(crate) total_status_size: usize,
    pub(crate) data_section: NonNull<u8>,
    pub(crate) status_section: NonNull<PerCpuRingHeader>,
}

unsafe impl Send for PerCpuRingBuffer {}
unsafe impl Sync for PerCpuRingBuffer {}

impl PerCpuRingBuffer {
    /// Internal reservation and write engine handling IRQL elevation, circular wrapping,
    /// sentinel emission, and KASLR zero-padding.
    ///
    /// # Arguments
    ///
    /// * `cpu_id` - Target logical processor index.
    /// * `event_type` - Numeric discriminator for the telemetry event.
    /// * `payload_len` - Serialized payload byte length.
    /// * `write_fn` - Closure writing the payload directly into the reserved slot.
    ///
    /// # Return values
    ///
    /// * `Ok(())` - Event committed successfully.
    /// * `Err(RingBufferError::InvalidCpuIndex)` - Target CPU index exceeds core count.
    /// * `Err(RingBufferError::DataMemoryAllocationFailed)` - Target core buffer partition is full.
    fn reserve_and_write<W>(
        &self,
        cpu_id: u32,
        event_type: u16,
        payload_len: usize,
        write_fn: W,
    ) -> Result<(), RingBufferError>
    where
        W: FnOnce(*mut u8),
    {
        if cpu_id >= self.cpu_count {
            return Err(RingBufferError::InvalidCpuIndex);
        }

        let record_size = core::mem::size_of::<EventHeader>()
            .checked_add(payload_len)
            .ok_or(RingBufferError::DataMemoryAllocationFailed)?;

        let aligned_record_size = record_size
            .checked_next_multiple_of(8)
            .ok_or(RingBufferError::DataMemoryAllocationFailed)?;

        // Elevate to DISPATCH_LEVEL to prevent thread preemption and core migration
        let _guard = DispatchIrqlGuard::raise();

        let header = unsafe { &*self.status_section.as_ptr().add(cpu_id as usize) };
        let cpu_data_base = unsafe {
            self.data_section
                .as_ptr()
                .add((cpu_id as usize) * PER_CPU_DATA_SIZE)
        };

        let current_write = header.write_cursor.load(Ordering::Relaxed) as usize;
        let current_read = header.read_cursor.load(Ordering::Acquire) as usize;

        let (target_offset, new_write) = if current_write >= current_read {
            if current_write + aligned_record_size <= PER_CPU_DATA_SIZE {
                if current_read == 0 && current_write + aligned_record_size == PER_CPU_DATA_SIZE {
                    header.dropped_events.fetch_add(1, Ordering::Relaxed);
                    return Err(RingBufferError::DataMemoryAllocationFailed);
                }
                (current_write, current_write + aligned_record_size)
            } else {
                // Must wrap to byte 0
                if current_read <= aligned_record_size {
                    header.dropped_events.fetch_add(1, Ordering::Relaxed);
                    return Err(RingBufferError::DataMemoryAllocationFailed);
                }

                // Place wrap sentinel if space allows
                if current_write + core::mem::size_of::<EventHeader>() <= PER_CPU_DATA_SIZE {
                    let wrap_header = EventHeader {
                        magic: EVENT_MAGIC,
                        event_type: EVENT_TYPE_WRAP,
                        payload_len: 0,
                        timestamp: 0,
                        cpu_id,
                        _reserved: 0,
                    };
                    unsafe {
                        let dst = cpu_data_base.add(current_write).cast::<EventHeader>();
                        dst.write_unaligned(wrap_header);
                    }
                }

                (0, aligned_record_size)
            }
        } else {
            let available = current_read - current_write - 1;
            if aligned_record_size > available {
                header.dropped_events.fetch_add(1, Ordering::Relaxed);
                return Err(RingBufferError::DataMemoryAllocationFailed);
            }
            (current_write, current_write + aligned_record_size)
        };

        let timestamp = unsafe {
            wdk_sys::ntddk::KeQueryPerformanceCounter(core::ptr::null_mut()).QuadPart as u64
        };

        let event_header = EventHeader {
            magic: EVENT_MAGIC,
            event_type,
            payload_len: payload_len as u32,
            timestamp,
            cpu_id,
            _reserved: 0,
        };

        unsafe {
            let base_ptr = cpu_data_base.add(target_offset);
            base_ptr.cast::<EventHeader>().write_unaligned(event_header);

            let payload_dst = base_ptr.add(core::mem::size_of::<EventHeader>());
            write_fn(payload_dst);

            // Zero alignment padding bytes to eliminate KASLR information disclosure
            let padding_len = aligned_record_size - record_size;
            if padding_len > 0 {
                payload_dst.add(payload_len).write_bytes(0, padding_len);
            }
        }

        // Commit updated write cursor with Release ordering
        header.write_cursor.store(new_write as u32, Ordering::Release);

        Ok(())
    }

    /// Writes an arbitrary binary payload and event type into the specified CPU core's partition.
    ///
    /// Elevates IRQL to `DISPATCH_LEVEL` via [`DispatchIrqlGuard`] for thread preemption safety on the
    /// executing core, reserves space in the ring buffer, copies the record header and payload, and commits
    /// the new write cursor.
    ///
    /// # Arguments
    ///
    /// * `cpu_id` - Target logical processor index.
    /// * `event_type` - Numeric discriminator for the telemetry event.
    /// * `payload` - Raw serialized byte slice.
    ///
    /// # Return values
    ///
    /// * `Ok(())` - Event written successfully.
    /// * `Err(RingBufferError::InvalidCpuIndex)` - Target CPU index exceeds core count.
    /// * `Err(RingBufferError::DataMemoryAllocationFailed)` - Target core buffer partition is full.
    #[allow(dead_code)]
    pub(crate) fn write_event(
        &self,
        cpu_id: u32,
        event_type: u16,
        payload: &[u8],
    ) -> Result<(), RingBufferError> {
        self.reserve_and_write(cpu_id, event_type, payload.len(), |dest| unsafe {
            core::ptr::copy_nonoverlapping(payload.as_ptr(), dest, payload.len());
        })
    }

    /// Serializes and writes a strongly-typed [`DriverEvent`] directly into the current CPU core's partition.
    ///
    /// Automatically queries the executing processor index and invokes [`DriverEvent::write_payload`]
    /// directly into the claimed slot with zero intermediate copies.
    ///
    /// # Arguments
    ///
    /// * `event` - Reference to the strongly-typed driver event instance.
    ///
    /// # Return values
    ///
    /// * `Ok(())` - Event written successfully.
    /// * `Err(RingBufferError::InvalidCpuIndex)` - Processor index exceeds core count.
    /// * `Err(RingBufferError::DataMemoryAllocationFailed)` - Partition is full.
    pub(crate) fn write_driver_event<E: DriverEvent>(&self, event: &E) -> Result<(), RingBufferError> {
        let cpu_id = unsafe { wdk_sys::ntddk::KeGetCurrentProcessorNumberEx(core::ptr::null_mut()) };
        self.reserve_and_write(cpu_id, event.event_type() as u16, event.payload_len(), |dest| unsafe {
            event.write_payload(dest);
        })
    }
}
