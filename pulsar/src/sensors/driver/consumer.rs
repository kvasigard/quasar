//! Per-CPU ring buffer consumer and multi-core partition manager.
//!
//! Provides lock-free SPSC consumption across individual per-CPU circular memory partitions,
//! handling wrap sentinels, 8-byte alignment strides, and atomic cursor progression.

use core::sync::atomic::Ordering;
use shared::ring_buffer::{
    EVENT_MAGIC, EVENT_TYPE_WRAP, EventHeader, PerCpuRingHeader,
};
use windows_sys::Win32::System::Performance::{QueryPerformanceCounter, QueryPerformanceFrequency};

/// Consumer for an individual logical CPU core's ring buffer partition.
pub struct CpuRingConsumer {
    pub cpu_id: u32,
    header: *const PerCpuRingHeader,
    data: *const u8,
    data_size: usize,
    pub current_read: usize,
    qpc_frequency: u64,
}

unsafe impl Send for CpuRingConsumer {}
unsafe impl Sync for CpuRingConsumer {}

impl CpuRingConsumer {
    /// Constructs a new consumer targeting a specific CPU core's partition.
    pub fn new(
        cpu_id: u32,
        status_base: u64,
        data_base: u64,
        status_stride: usize,
        data_stride: usize,
        qpc_freq: u64,
    ) -> Self {
        let header_ptr = (status_base + (cpu_id as u64 * status_stride as u64))
            as *const PerCpuRingHeader;
        let data_ptr = (data_base + (cpu_id as u64 * data_stride as u64)) as *const u8;

        Self {
            cpu_id,
            header: header_ptr,
            data: data_ptr,
            data_size: data_stride,
            current_read: 0,
            qpc_frequency: qpc_freq,
        }
    }

    /// Checks if this core has unread telemetry events pending in its partition.
    #[inline(always)]
    pub fn has_pending_events(&self) -> bool {
        let header = unsafe { &*self.header };
        header.write_cursor.load(Ordering::Acquire) as usize != self.current_read
    }

    /// Calculates end-to-end transport latency in microseconds using QPC timestamps.
    #[inline(always)]
    pub fn compute_latency_us(&self, kernel_timestamp: u64, current_qpc: u64) -> f64 {
        if current_qpc > kernel_timestamp && self.qpc_frequency > 0 {
            let ticks = current_qpc - kernel_timestamp;
            (ticks as f64 * 1_000_000.0) / (self.qpc_frequency as f64)
        } else {
            0.0
        }
    }

    /// Drains all available event records from this core's partition.
    ///
    /// # Arguments
    /// * `callback` - Invoked for each decoded event with `(cpu_id, event_type, latency_us, payload)`.
    ///
    /// # Returns
    /// The total number of events drained in this pass.
    pub fn drain<F>(&mut self, mut callback: F) -> usize
    where
        F: FnMut(u32, u16, f64, &[u8]),
    {
        let header = unsafe { &*self.header };
        let write_cursor = header.write_cursor.load(Ordering::Acquire) as usize;
        let mut events_drained = 0;

        let mut current_qpc = 0i64;
        unsafe {
            QueryPerformanceCounter(&raw mut current_qpc);
        }

        while self.current_read != write_cursor {
            if self.current_read + core::mem::size_of::<EventHeader>() > self.data_size {
                self.current_read = 0;
                continue;
            }

            let event_ptr = unsafe { self.data.add(self.current_read) };
            let event_header = unsafe { event_ptr.cast::<EventHeader>().read() };

            if event_header.magic != EVENT_MAGIC {
                log::warn!(
                    target: "driver_consumer",
                    "[CPU {}] Invalid magic {:#06X} at read offset {}. Advancing cursor.",
                    self.cpu_id,
                    event_header.magic,
                    self.current_read
                );
                break;
            }

            if event_header.event_type == EVENT_TYPE_WRAP {
                self.current_read = 0;
                continue;
            }

            let payload_len = event_header.payload_len as usize;
            let record_size = core::mem::size_of::<EventHeader>() + payload_len;
            let aligned_record_size = (record_size + 7) & !7;

            let payload_ptr = unsafe { event_ptr.add(core::mem::size_of::<EventHeader>()) };
            let payload = unsafe { core::slice::from_raw_parts(payload_ptr, payload_len) };

            let latency_us = self.compute_latency_us(event_header.timestamp, current_qpc as u64);
            callback(self.cpu_id, event_header.event_type, latency_us, payload);

            self.current_read += aligned_record_size;
            events_drained += 1;
        }

        // Commit updated read cursor with Release ordering
        header
            .read_cursor
            .store(self.current_read as u32, Ordering::Release);

        events_drained
    }

    /// Queries the total number of events dropped on this core due to buffer exhaustion.
    #[inline(always)]
    pub fn dropped_events(&self) -> u32 {
        unsafe { (*self.header).dropped_events.load(Ordering::Relaxed) }
    }
}

/// Coordinates round-robin consumption across all per-CPU core partitions.
pub struct DriverRingManager {
    consumers: Vec<CpuRingConsumer>,
}

impl DriverRingManager {
    /// Initializes consumers for all active logical CPU partitions described in the response.
    pub fn new(mapping: &shared::ioctl::PerCpuMapResponse) -> Self {
        let mut freq = 0i64;
        unsafe {
            QueryPerformanceFrequency(&raw mut freq);
        }

        let mut consumers = Vec::with_capacity(mapping.cpu_count as usize);
        for cpu_id in 0..mapping.cpu_count {
            consumers.push(CpuRingConsumer::new(
                cpu_id,
                mapping.status_address,
                mapping.data_address,
                mapping.per_cpu_status_size as usize,
                mapping.per_cpu_data_size as usize,
                freq as u64,
            ));
        }

        Self { consumers }
    }

    /// Checks if any core partition has pending unread telemetry events.
    #[inline(always)]
    pub fn has_pending_events(&self) -> bool {
        self.consumers.iter().any(|c| c.has_pending_events())
    }

    /// Drains all available events across all core partitions.
    pub fn drain_all<F>(&mut self, mut callback: F) -> usize
    where
        F: FnMut(u32, u16, f64, &[u8]),
    {
        let mut total = 0;
        for consumer in &mut self.consumers {
            total += consumer.drain(&mut callback);
        }
        total
    }

    /// Sums total dropped events across all active cores.
    pub fn total_dropped_events(&self) -> u32 {
        self.consumers.iter().map(|c| c.dropped_events()).sum()
    }

    /// Returns per-core dropped event counts.
    pub fn per_cpu_drops(&self) -> Vec<u32> {
        self.consumers.iter().map(|c| c.dropped_events()).collect()
    }
}

/// Backward-compatible alias for [`CpuRingConsumer`].
pub type PerCpuConsumer = CpuRingConsumer;

/// Backward-compatible alias for [`DriverRingManager`].
pub type MultiCpuRingManager = DriverRingManager;
