//! Lock-free, zero-spin event queue writing algorithms for per-CPU partitions.
//!
//! Provides the core single-producer commit logic for writing telemetry events directly
//! into per-CPU circular memory partitions without locks, CAS loops, or cross-core contention.

use core::ptr::NonNull;
use core::sync::atomic::{AtomicU32, Ordering};

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
    /// Kernel-private producer write cursors (one per CPU core), isolated from user-mode writable memory.
    pub(crate) producer_cursors: NonNull<AtomicU32>,
}

unsafe impl Send for PerCpuRingBuffer {}
unsafe impl Sync for PerCpuRingBuffer {}

impl PerCpuRingBuffer {
    /// Synchronizes all user-visible read and write cursors with the authoritative kernel producer cursors.
    ///
    /// Invoked when establishing a new user-mode session so the reader starts from the current
    /// kernel write offset on each CPU partition.
    pub(crate) fn sync_read_cursors(&self) {
        for cpu in 0..(self.cpu_count as usize) {
            let write_pos = unsafe { &*self.producer_cursors.as_ptr().add(cpu) }
                .load(Ordering::Acquire);
            let header = unsafe { &*self.status_section.as_ptr().add(cpu) };
            header.write_cursor.store(write_pos, Ordering::Release);
            header.read_cursor.store(write_pos, Ordering::Release);
        }
    }

    /// Internal reservation and write engine handling circular wrapping,
    /// sentinel emission, and KASLR zero-padding.
    ///
    /// Caller must already hold [`DispatchIrqlGuard`] (running at `DISPATCH_LEVEL`) so the
    /// executing thread cannot migrate between cores.
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
    /// * `Err(RingBufferError::InvalidParameter)` - Untrusted read cursor or record size is invalid.
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

        if aligned_record_size == 0 || aligned_record_size >= PER_CPU_DATA_SIZE {
            return Err(RingBufferError::InvalidParameter);
        }

        let header = unsafe { &*self.status_section.as_ptr().add(cpu_id as usize) };
        let producer_cursor = unsafe { &*self.producer_cursors.as_ptr().add(cpu_id as usize) };
        let cpu_data_base = unsafe {
            self.data_section
                .as_ptr()
                .add((cpu_id as usize) * PER_CPU_DATA_SIZE)
        };

        // Load authoritative write cursor from kernel-private memory (immune to user-mode tampering)
        let current_write = producer_cursor.load(Ordering::Relaxed) as usize;
        // Load untrusted user-mode read cursor and strictly validate bounds & 8-byte alignment
        let current_read = header.read_cursor.load(Ordering::Acquire) as usize;
        if current_read >= PER_CPU_DATA_SIZE || !current_read.is_multiple_of(8) {
            header.dropped_events.fetch_add(1, Ordering::Relaxed);
            return Err(RingBufferError::InvalidParameter);
        }

        let (target_offset, new_write) = if current_write >= current_read {
            if current_write + aligned_record_size <= PER_CPU_DATA_SIZE {
                let candidate_write = current_write + aligned_record_size;
                if candidate_write == PER_CPU_DATA_SIZE {
                    // Wrapping to 0 when current_read == 0 would make the buffer indistinguishable from empty
                    if current_read == 0 {
                        header.dropped_events.fetch_add(1, Ordering::Relaxed);
                        return Err(RingBufferError::DataMemoryAllocationFailed);
                    }
                    (current_write, 0)
                } else {
                    (current_write, candidate_write)
                }
            } else {
                // Must wrap to byte 0
                if current_read <= aligned_record_size {
                    header.dropped_events.fetch_add(1, Ordering::Relaxed);
                    return Err(RingBufferError::DataMemoryAllocationFailed);
                }

                // Place wrap sentinel if at least sizeof(EventHeader) (24 bytes) remains at the tail
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

        // Defensive bounds verification prior to raw pointer write
        if target_offset
            .checked_add(aligned_record_size)
            .is_none_or(|end| end > PER_CPU_DATA_SIZE)
        {
            return Err(RingBufferError::InvalidParameter);
        }

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

        // Update kernel-private authoritative write cursor and publish to user-mode status header
        producer_cursor.store(new_write as u32, Ordering::Relaxed);
        header
            .write_cursor
            .store(new_write as u32, Ordering::Release);

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
        let _guard = DispatchIrqlGuard::raise();
        self.reserve_and_write(cpu_id, event_type, payload.len(), |dest| unsafe {
            core::ptr::copy_nonoverlapping(payload.as_ptr(), dest, payload.len());
        })
    }

    /// Serializes and writes a strongly-typed [`DriverEvent`] directly into the current CPU core's partition.
    ///
    /// Elevates IRQL to `DISPATCH_LEVEL` before querying the executing processor index so the thread
    /// cannot migrate cores between processor lookup and buffer reservation, then invokes
    /// [`DriverEvent::write_payload`] directly into the claimed slot with zero intermediate copies.
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
        // Elevate IRQL to DISPATCH_LEVEL BEFORE reading the current processor number to prevent core migration!
        let _guard = DispatchIrqlGuard::raise();
        let cpu_id = unsafe { wdk_sys::ntddk::KeGetCurrentProcessorNumberEx(core::ptr::null_mut()) };
        self.reserve_and_write(cpu_id, event.event_type() as u16, event.payload_len(), |dest| unsafe {
            event.write_payload(dest);
        })
    }
}
