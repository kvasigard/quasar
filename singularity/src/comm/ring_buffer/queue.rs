use crate::comm::ring_buffer::error::RingBufferError;
use core::sync::atomic::{AtomicU16, AtomicU64, Ordering};
use shared::ring_buffer::{
    ConsumerStatusPage, DriverEvent, RECORD_MAGIC, RecordHeader, RecordStatus,
};

const HEADER_SIZE: usize = core::mem::size_of::<RecordHeader>();

/// Represents an exclusively reserved memory slot within the shared data buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ClaimedSlot {
    /// Byte offset from the base of the 4 MB data buffer where the record begins.
    pub offset: usize,
    /// Monotonic sequence number assigned to this specific slot reservation.
    pub sequence: u64,
    /// Total allocated frame size in bytes (including any absorbed tail slack).
    pub total_size: u32,
}

/// Non-owning transport view over the shared ring buffer memory and synchronization state.
pub(crate) struct RingQueue<'a> {
    pub data_buffer: *mut u8,
    pub capacity: usize,
    pub status_page: &'a ConsumerStatusPage,
    pub write_head: &'a AtomicU64,
    pub sequence: &'a AtomicU64,
}

impl<'a> RingQueue<'a> {
    /// Optimistically reserves an 8-byte aligned contiguous slot in the shared data buffer.
    ///
    /// Executes a lock-free Compare-And-Swap (CAS) ticket reservation loop across processor cores:
    ///
    /// 1. Clamps `user_tail` against `write_head` to eliminate unsigned integer underflow caused by
    ///    concurrent or corrupted user-mode updates.
    /// 2. Verifies buffer capacity against unconsumed backlog, atomically incrementing `dropped_events`
    ///    and failing fast if the buffer is full without blocking the calling thread.
    /// 3. Emits an atomic [`RecordStatus::Wrap`] sentinel header if contiguous space at the tail cannot
    ///    fit the record, advancing `write_head` past the tail and restarting reservation at offset 0.
    /// 4. Absorbs any trailing slack smaller than [`RecordHeader`] (32 bytes) into the allocation to
    ///    prevent unreachable runt memory gaps at the buffer boundary.
    ///
    /// Safe to call concurrently from any processor core at `IRQL <= DISPATCH_LEVEL`.
    ///
    /// # Arguments
    ///
    /// * `required_size` - Pre-calculated 8-byte aligned frame size in bytes (header + payload + padding).
    ///
    /// # Return values
    ///
    /// * `Ok(ClaimedSlot)` - Offset, sequence number, and total size of the reserved slot.
    /// * `Err(RingBufferError::BufferFull)` - Buffer is full; `dropped_events` counter was incremented.
    /// * `Err(RingBufferError::InvalidParameter)` - `required_size` is zero or exceeds total buffer capacity.
    pub fn reserve_slot(&self, required_size: u32) -> Result<ClaimedSlot, RingBufferError> {
        if required_size == 0 || (required_size as usize) > self.capacity {
            return Err(RingBufferError::InvalidParameter);
        }

        let capacity = self.capacity as u64;

        loop {
            // Read the current monotonic write cursor
            let write_head = self.write_head.load(Ordering::Acquire);

            // User mode updates user_tail asynchronously; clamping prevents unsigned integer
            // underflow if user_tail exceeds write_head due to racing reads or state reset.
            let user_tail = self
                .status_page
                .user_tail
                .load(Ordering::Acquire)
                .min(write_head);

            // Fast-fail if the unconsumed backlog cannot accommodate the requested record.
            // Push operations run at IRQL <= DISPATCH_LEVEL and cannot block, so capacity
            // exhaustion drops the event immediately.
            if (write_head - user_tail) + (required_size as u64) > capacity {
                self.status_page
                    .dropped_events
                    .fetch_add(1, Ordering::Relaxed);
                return Err(RingBufferError::BufferFull);
            }

            let offset = (write_head % capacity) as usize;
            let remaining_tail = self.capacity - offset;

            // When a record exceeds the remaining tail, records are never fragmented across
            // the buffer boundary. Instead, the remaining tail is retired and the cursor wraps
            // to offset 0. A RecordStatus::Wrap sentinel is published so the consumer knows to
            // wrap around rather than reading uninitialized memory.
            if (required_size as usize) > remaining_tail {
                if self
                    .write_head
                    .compare_exchange_weak(
                        write_head,
                        write_head + (remaining_tail as u64),
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    )
                    .is_ok()
                {
                    // Fetch sequence immediately upon winning CAS to preserve monotonic stream ordering
                    let wrap_sequence = self.sequence.fetch_add(1, Ordering::Relaxed);
                    debug_assert!(
                        remaining_tail == 0 || remaining_tail >= HEADER_SIZE,
                        "tail slack absorption guarantees remaining_tail is either 0 or >= HEADER_SIZE"
                    );
                    if remaining_tail >= HEADER_SIZE {
                        unsafe {
                            self.write_wrap_sentinel(offset, remaining_tail as u32, wrap_sequence)
                        };
                    }
                }
                core::hint::spin_loop();
                continue;
            }

            // If allocating this record would leave a trailing slack smaller than a RecordHeader
            // (< 32 bytes), absorb that slack into this record. Otherwise, a future wrap at the
            // buffer end would have insufficient room to write a 32-byte wrap sentinel header.
            let remaining_after = remaining_tail - (required_size as usize);
            let actual_size = if (1..HEADER_SIZE).contains(&remaining_after) {
                required_size + (remaining_after as u32)
            } else {
                required_size
            };

            if self
                .write_head
                .compare_exchange_weak(
                    write_head,
                    write_head + (actual_size as u64),
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                return Ok(ClaimedSlot {
                    offset,
                    sequence: self.sequence.fetch_add(1, Ordering::Relaxed),
                    total_size: actual_size,
                });
            }

            core::hint::spin_loop();
        }
    }

    /// Emits a [`RecordStatus::Wrap`] sentinel header at the buffer tail.
    ///
    /// The user-mode consumer sequentially parses records by inspecting each header's size.
    /// When an allocation wraps around to offset 0, this sentinel header instructs the
    /// consumer that no further valid events exist in the current buffer cycle and to wrap
    /// its reading cursor directly to offset 0.
    ///
    /// # Safety
    ///
    /// * `offset + (total_size as usize) <= self.capacity`.
    /// * `total_size >= HEADER_SIZE`.
    /// * The caller must hold exclusive reservation for the memory slice `[offset, offset + total_size)`.
    unsafe fn write_wrap_sentinel(&self, offset: usize, total_size: u32, sequence: u64) {
        let header_ptr = unsafe { self.data_buffer.add(offset) as *mut RecordHeader };
        let timestamp = unsafe {
            let qpc = wdk_sys::ntddk::KeQueryPerformanceCounter(core::ptr::null_mut());
            qpc.QuadPart
        };

        // Stage the sentinel header with status set to Reserved
        unsafe {
            core::ptr::write(
                header_ptr,
                RecordHeader {
                    magic: RECORD_MAGIC,
                    total_size,
                    sequence,
                    timestamp,
                    event_type: 0,
                    status: AtomicU16::new(RecordStatus::Reserved as u16),
                    _reserved: 0,
                },
            );
        }

        // Publish Wrap status with Release ordering so the consumer safely observes the sentinel
        unsafe {
            (*header_ptr)
                .status
                .store(RecordStatus::Wrap as u16, Ordering::Release);
        }
    }

    /// Writes the event header and payload into a reserved slot, committing it atomically.
    ///
    /// Serializes [`RecordHeader`] and the event payload directly into non-paged memory, zero-fills
    /// any trailing alignment padding to eliminate uninitialized kernel memory disclosure hazards, and
    /// issues an atomic store with `Ordering::Release` to transition the status to [`RecordStatus::Committed`].
    ///
    /// Safe to call concurrently from any processor core at `IRQL <= DISPATCH_LEVEL`.
    ///
    /// # Arguments
    ///
    /// * `slot` - Exclusively reserved slot coordinates obtained from [`Self::reserve_slot`].
    /// * `event` - Event payload implementing [`DriverEvent`].
    ///
    /// # Safety
    ///
    /// The caller must guarantee:
    /// * `slot` was produced by a successful call to [`Self::reserve_slot`] on this queue.
    /// * The memory range `[slot.offset, slot.offset + slot.total_size)` lies entirely within `capacity`.
    /// * No other thread or processor core concurrently writes to this reserved memory slice.
    pub unsafe fn commit_event(&self, slot: ClaimedSlot, event: &impl DriverEvent) {
        let slot_ptr = unsafe { self.data_buffer.add(slot.offset) };
        let header_ptr = slot_ptr as *mut RecordHeader;

        let timestamp = unsafe {
            let qpc = wdk_sys::ntddk::KeQueryPerformanceCounter(core::ptr::null_mut());
            qpc.QuadPart
        };

        // Write RecordHeader into the reserved slot with status set to Reserved (0)
        unsafe {
            core::ptr::write(
                header_ptr,
                RecordHeader {
                    magic: RECORD_MAGIC,
                    total_size: slot.total_size,
                    sequence: slot.sequence,
                    timestamp,
                    event_type: event.event_type() as u16,
                    status: AtomicU16::new(RecordStatus::Reserved as u16),
                    _reserved: 0,
                },
            );
        }

        // Copy payload bytes directly into the memory region immediately following the header
        let payload_dest = unsafe { slot_ptr.add(HEADER_SIZE) };
        let payload_len = event.payload_len();
        unsafe {
            event.write_payload(payload_dest);
        }

        // Zero-fill any trailing padding bytes between payload end and total_size
        let written_bytes = HEADER_SIZE + payload_len;
        if (slot.total_size as usize) > written_bytes {
            let padding_len = (slot.total_size as usize) - written_bytes;
            unsafe {
                core::ptr::write_bytes(slot_ptr.add(written_bytes), 0, padding_len);
            }
        }

        // Atomically commit the record with Release ordering, making header and payload visible
        unsafe {
            (*header_ptr)
                .status
                .store(RecordStatus::Committed as u16, Ordering::Release);
        }
    }
}

/// Computes the total frame size (header + payload), padded to an 8-byte boundary.
pub(crate) fn calculate_event_size(event: &impl DriverEvent) -> Result<u32, RingBufferError> {
    let payload_len = event.payload_len();

    // 32-byte header + payload bytes
    // Returns error if the size exceeds the u32::MAX number
    let raw_size = HEADER_SIZE
        .checked_add(payload_len)
        .ok_or(RingBufferError::InvalidParameter)?;

    let aligned_size = raw_size
        .checked_next_multiple_of(8)
        .ok_or(RingBufferError::InvalidParameter)?;

    u32::try_from(aligned_size).map_err(|_| RingBufferError::InvalidParameter)
}
