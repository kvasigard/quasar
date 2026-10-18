extern crate alloc;
use alloc::boxed::Box;
use core::ffi::c_void;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicPtr, AtomicU32, Ordering};

use shared::ioctl::PerCpuMapResponse;
use shared::ring_buffer::{DriverEvent, PER_CPU_DATA_SIZE, PerCpuRingHeader};

use wdk_sys::{
    _MM_PAGE_PRIORITY::NormalPagePriority,
    ALL_PROCESSOR_GROUPS, DISPATCH_LEVEL, MdlMappingNoExecute, MdlMappingNoWrite, NTSTATUS,
    PASSIVE_LEVEL, SIZE_T, STATUS_ACCESS_DENIED, ULONG, WDFFILEOBJECT,
    ntddk::{ExAllocatePool2, ExFreePoolWithTag, IoGetCurrentProcess},
};

use super::error::RingBufferError;
use super::mdl::MdlSection;
use super::notifier::KernelNotificationEvent;
use super::queue::PerCpuRingBuffer;
use super::session::UserModeMemory;
use crate::foundation::ensure_max_irql;
use crate::foundation::raii::KernelSpinLock;

use crate::wrappers::PoolFlag;

/// 4-byte pool tag identifier for ring buffer memory allocations ('QSAR').
const POOL_TAG: ULONG = u32::from_ne_bytes(*b"QSAR");

/// Standard Windows x64 virtual memory page size (4 KB).
///
/// In the NT kernel, pool allocations >= 4096 bytes are satisfied via `ExpAllocateBigPoolPages`,
/// ensuring 4KB page alignment (addr % 4096 == 0). Since 4096 is a multiple of 64, this satisfies
/// `PerCpuRingHeader` cache-line alignment and eliminates user-mode pool sharing vulnerabilities.
const PAGE_SIZE: usize = 4096;

/// Lifecycle state machine for user-mode MDL mappings.
pub(crate) enum MappingState {
    /// No active user-mode session is mapped.
    Unmapped,
    /// A thread is currently building and mapping MDLs at `PASSIVE_LEVEL`.
    MappingInProgress {
        file_object: usize,
        #[allow(dead_code)]
        owner_process: usize,
        cancel_requested: bool,
    },
    /// User-mode MDL pages are actively mapped into `owner_process`.
    Mapped(UserModeMemory),
}

impl PerCpuRingBuffer {
    /// Detects active logical processor count and allocates contiguous NonPaged pool for all cores.
    ///
    /// Determines the number of active logical processors in the host system and allocates
    /// dedicated, page-aligned NonPaged pool regions for the telemetry data buffer, status
    /// headers, and kernel-private producer cursors. Backing pool memory is fully zero-initialized.
    ///
    /// # Return values
    ///
    /// * `Ok(Self)` - Backing memory pool buffers successfully allocated and zero-initialized.
    /// * `Err(RingBufferError::DataMemoryAllocationFailed)` - Memory manager could not satisfy data pool allocation or page alignment.
    /// * `Err(RingBufferError::StatusMemoryAllocationFailed)` - Memory manager could not satisfy status pool allocation or 64-byte alignment.
    pub(crate) fn new() -> Result<Self, RingBufferError> {
        let detected =
            unsafe { wdk_sys::ntddk::KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS as u16) };
        let cpu_count = if detected == 0 { 1 } else { detected };

        let total_data_size = (cpu_count as usize) * PER_CPU_DATA_SIZE;
        let required_status_size = (cpu_count as usize) * core::mem::size_of::<PerCpuRingHeader>();
        let total_status_size = required_status_size.next_multiple_of(PAGE_SIZE);
        let producer_cursors_size =
            (cpu_count as usize) * core::mem::size_of::<AtomicU32>();

        crate::driver_debug!(
            "[ring_buffer::new] Detected {cpu_count} CPU cores (Data: {total_data_size} bytes, Status: {total_status_size} bytes [required: {required_status_size} bytes])"
        );

        let pool_flag = PoolFlag::NonPaged.to_ulong64();

        let data_raw = unsafe { ExAllocatePool2(pool_flag, total_data_size as SIZE_T, POOL_TAG) };
        if !(data_raw as usize).is_multiple_of(PAGE_SIZE) {
            crate::driver_error!(
                "[ring_buffer::new] Data pool allocation failed or not page-aligned ({data_raw:p})"
            );
            if !data_raw.is_null() {
                unsafe {
                    ExFreePoolWithTag(data_raw, POOL_TAG);
                }
            }
            return Err(RingBufferError::DataMemoryAllocationFailed);
        }
        let data_section = match NonNull::new(data_raw as *mut u8) {
            Some(ptr) => ptr,
            None => {
                crate::driver_error!(
                    "[ring_buffer::new] Failed to allocate data pool ({total_data_size} bytes)"
                );
                return Err(RingBufferError::DataMemoryAllocationFailed);
            }
        };

        let status_raw =
            unsafe { ExAllocatePool2(pool_flag, total_status_size as SIZE_T, POOL_TAG) };
        if !(status_raw as usize).is_multiple_of(core::mem::align_of::<PerCpuRingHeader>()) {
            crate::driver_error!(
                "[ring_buffer::new] Status pool pointer {status_raw:p} is not 64-byte aligned"
            );
            if !status_raw.is_null() {
                unsafe {
                    ExFreePoolWithTag(status_raw, POOL_TAG);
                }
            }
            unsafe {
                ExFreePoolWithTag(data_section.as_ptr().cast(), POOL_TAG);
            }
            return Err(RingBufferError::StatusMemoryAllocationFailed);
        }
        let status_section = match NonNull::new(status_raw as *mut PerCpuRingHeader) {
            Some(ptr) => ptr,
            None => {
                crate::driver_error!(
                    "[ring_buffer::new] Failed to allocate status pool ({total_status_size} bytes)"
                );
                unsafe {
                    ExFreePoolWithTag(data_section.as_ptr().cast(), POOL_TAG);
                }
                return Err(RingBufferError::StatusMemoryAllocationFailed);
            }
        };

        let cursors_raw =
            unsafe { ExAllocatePool2(pool_flag, producer_cursors_size as SIZE_T, POOL_TAG) };
        let producer_cursors = match NonNull::new(cursors_raw as *mut AtomicU32) {
            Some(ptr) => ptr,
            None => {
                crate::driver_error!(
                    "[ring_buffer::new] Failed to allocate kernel producer cursors ({producer_cursors_size} bytes)"
                );
                unsafe {
                    ExFreePoolWithTag(status_section.as_ptr().cast(), POOL_TAG);
                    ExFreePoolWithTag(data_section.as_ptr().cast(), POOL_TAG);
                }
                return Err(RingBufferError::StatusMemoryAllocationFailed);
            }
        };

        // Explicitly zero-initialize the allocated status page(s) and kernel producer cursors
        unsafe {
            core::ptr::write_bytes(status_raw as *mut u8, 0, total_status_size);
            core::ptr::write_bytes(cursors_raw as *mut u8, 0, producer_cursors_size);
        }

        crate::driver_debug!(
            "[ring_buffer::new] Backing pool memory allocated and zero-initialized"
        );
        Ok(PerCpuRingBuffer {
            cpu_count,
            total_data_size,
            total_status_size,
            data_section,
            status_section,
            producer_cursors,
        })
    }

    /// Projects the contiguous per-CPU memory pools into the virtual address space of the calling process.
    ///
    /// Configures the data section as read-only (`MdlMappingNoWrite`) and the status section as read-write.
    /// Executes at `PASSIVE_LEVEL` in the context of the calling user-mode process.
    ///
    /// # Arguments
    ///
    /// * `file_object` - Originating `WDFFILEOBJECT` pointer value.
    /// * `owner_process` - Originating `PEPROCESS` pointer value.
    ///
    /// # Return values
    ///
    /// * `Ok(UserModeMemory)` - Mappings created and packaged into an active user session.
    /// * `Err(RingBufferError::MdlAllocationFailed)` - MDL allocation failed.
    /// * `Err(RingBufferError::MdlMappingFailed)` - MDL virtual memory mapping into process failed.
    pub(crate) fn create_user_mapping(
        &self,
        file_object: usize,
        owner_process: usize,
    ) -> Result<UserModeMemory, RingBufferError> {
        let data_priority = (NormalPagePriority as u32) | MdlMappingNoExecute | MdlMappingNoWrite;
        let status_priority = (NormalPagePriority as u32) | MdlMappingNoExecute;

        let data_section = unsafe {
            MdlSection::new(
                self.data_section.cast::<c_void>(),
                self.total_data_size as u32,
                data_priority,
            )?
        };
        let status_section = unsafe {
            MdlSection::new(
                self.status_section.cast::<c_void>(),
                self.total_status_size as u32,
                status_priority,
            )?
        };

        Ok(UserModeMemory::new(
            data_section,
            status_section,
            self.cpu_count,
            file_object,
            owner_process,
        ))
    }
}

impl Drop for PerCpuRingBuffer {
    fn drop(&mut self) {
        unsafe {
            ExFreePoolWithTag(self.producer_cursors.as_ptr().cast(), POOL_TAG);
            ExFreePoolWithTag(self.status_section.as_ptr().cast(), POOL_TAG);
            ExFreePoolWithTag(self.data_section.as_ptr().cast(), POOL_TAG);
        }
    }
}

/// Singleton manager for the per-CPU shared memory ring buffer and active user mapping.
pub struct RingBufferManager {
    /// Atomic pointer providing lock-free access for high-frequency producer cores,
    /// decoupling hot-path telemetry writes from user-session management locks.
    ring_buffer: AtomicPtr<PerCpuRingBuffer>,

    /// Serializes user-mode mapping transitions and guards against race conditions where
    /// an asynchronous producer core calls `signal_reader()` while the session is being torn down.
    active_mapping: KernelSpinLock<MappingState>,
}

impl Default for RingBufferManager {
    fn default() -> Self {
        Self::new()
    }
}

impl RingBufferManager {
    /// Constructs a new uninitialized `RingBufferManager`.
    ///
    /// Initializes internal atomic references to null and the active mapping lock to `MappingState::Unmapped`.
    ///
    /// # Return values
    ///
    /// * `Self` - Uninitialized ring buffer manager instance.
    pub const fn new() -> Self {
        Self {
            ring_buffer: AtomicPtr::new(core::ptr::null_mut()),
            active_mapping: KernelSpinLock::new(MappingState::Unmapped),
        }
    }

    /// Checks whether the shared memory ring buffer is currently initialized and active.
    ///
    /// Inspects the underlying backing buffer pointer with acquire ordering.
    ///
    /// # Return values
    ///
    /// * `true` - Ring buffer backing memory is allocated and ready.
    /// * `false` - Ring buffer is uninitialized or torn down.
    #[inline(always)]
    pub(crate) fn is_active(&self) -> bool {
        !self.ring_buffer.load(Ordering::Acquire).is_null()
    }

    /// Allocates NonPaged pool memory for all logical processor partitions.
    ///
    /// Queries the active core count, allocates contiguous backing pool storage for data
    /// and status partitions, and publishes the reference atomically.
    ///
    /// # Return values
    ///
    /// * `Ok(())` - Backing memory partitions allocated and published.
    /// * `Err(RingBufferError::AlreadyInitialized)` - Ring buffer is already active.
    /// * `Err(RingBufferError::InvalidIrql)` - Execution IRQL exceeded `DISPATCH_LEVEL`.
    /// * `Err(RingBufferError::DataMemoryAllocationFailed)` - Pool allocation or alignment failed for data memory.
    /// * `Err(RingBufferError::StatusMemoryAllocationFailed)` - Pool allocation or alignment failed for status memory.
    pub(crate) fn initialize(&self) -> Result<(), RingBufferError> {
        if self.is_active() {
            crate::driver_warn!("[ring_buffer::initialize] Ring buffer is already initialized");
            return Err(RingBufferError::AlreadyInitialized);
        }

        if let Err(current_irql) = ensure_max_irql(DISPATCH_LEVEL as u8) {
            crate::driver_error!(
                "[ring_buffer::initialize] Invalid IRQL {current_irql} (must be <= DISPATCH_LEVEL)"
            );
            return Err(RingBufferError::InvalidIrql {
                current: current_irql,
                max: DISPATCH_LEVEL as u8,
            });
        }

        // The backing store must have a stable, non-movable address in pool memory across
        // the driver's lifetime, so we promote the stack-initialized buffer to a heap box.
        let ring_buffer = Box::new(PerCpuRingBuffer::new()?);
        let cpu_count = ring_buffer.cpu_count;
        let data_kb = (cpu_count as usize * PER_CPU_DATA_SIZE) / 1024;

        // Disarm Rust's automatic destructor so the allocation remains resident after this function returns.
        let raw = Box::into_raw(ring_buffer);

        // Atomically publish the pointer so readers observe fully initialized memory under Release semantics.
        if self
            .ring_buffer
            .compare_exchange(
                core::ptr::null_mut(),
                raw,
                Ordering::Release,
                Ordering::Relaxed,
            )
            .is_err()
        {
            // If another thread won the initialization race, reclaim ownership to trigger `Drop`
            // and release the backing NonPaged pool allocations rather than leaking them.
            unsafe {
                drop(Box::from_raw(raw));
            }
            return Err(RingBufferError::AlreadyInitialized);
        }

        crate::driver_info!(
            "[ring_buffer::initialize] Allocated Per-CPU ring buffers for {cpu_count} CPU cores ({data_kb} KB total)"
        );
        Ok(())
    }

    /// Releases all ring buffer memory and active user mappings.
    ///
    /// Tears down any outstanding user mapping sessions if running in the owning process context,
    /// and reclaims backing NonPaged pool allocations using atomic exchange.
    pub(crate) fn cleanup(&self) {
        let current_process = unsafe { IoGetCurrentProcess() } as usize;
        let extracted = {
            let mut guard = self.active_mapping.lock();
            match *guard {
                MappingState::Mapped(ref mem) if mem.owner_process() == current_process => {
                    match core::mem::replace(&mut *guard, MappingState::Unmapped) {
                        MappingState::Mapped(m) => Some(m),
                        _ => None,
                    }
                }
                MappingState::MappingInProgress {
                    ref mut cancel_requested,
                    ..
                } => {
                    *cancel_requested = true;
                    None
                }
                _ => None,
            }
        };
        // Drop UserModeMemory outside the spinlock at PASSIVE_LEVEL
        drop(extracted);

        let raw = self
            .ring_buffer
            .swap(core::ptr::null_mut(), Ordering::AcqRel);
        if !raw.is_null() {
            unsafe {
                drop(Box::from_raw(raw));
            }
            crate::driver_info!(
                "[ring_buffer::cleanup] Per-CPU ring buffer backing memory released"
            );
        }
    }

    /// Projects the contiguous per-CPU shared memory pools into the calling process address space.
    ///
    /// Builds MDLs for data (read-only) and status (read-write) sections and maps them
    /// into the calling user-mode process address space at `PASSIVE_LEVEL`.
    ///
    /// # Arguments
    ///
    /// * `file_object` - Originating `WDFFILEOBJECT` associated with the IOCTL request.
    ///
    /// # Return values
    ///
    /// * `Ok(PerCpuMapResponse)` - Response structure containing mapped user-mode base addresses and geometry.
    /// * `Err(RingBufferError::AlreadyMapped)` - An active user-mode mapping session is already established.
    /// * `Err(RingBufferError::DeviceStateInvalid)` - Ring buffer backing memory is uninitialized or cancelled.
    /// * `Err(RingBufferError)` - Mapping or MDL allocation failure.
    pub(crate) fn create_user_mapping(
        &self,
        file_object: WDFFILEOBJECT,
    ) -> Result<PerCpuMapResponse, RingBufferError> {
        if let Err(current_irql) = ensure_max_irql(PASSIVE_LEVEL as u8) {
            return Err(RingBufferError::InvalidIrql {
                current: current_irql,
                max: PASSIVE_LEVEL as u8,
            });
        }

        let ptr = self.ring_buffer.load(Ordering::Acquire);
        if ptr.is_null() {
            return Err(RingBufferError::DeviceStateInvalid);
        }
        let ring = unsafe { &*ptr };

        let file_obj_id = file_object as usize;
        let owner_process = unsafe { IoGetCurrentProcess() } as usize;

        {
            let mut guard = self.active_mapping.lock();
            if !matches!(*guard, MappingState::Unmapped) {
                return Err(RingBufferError::AlreadyMapped);
            }
            *guard = MappingState::MappingInProgress {
                file_object: file_obj_id,
                owner_process,
                cancel_requested: false,
            };
        }

        ring.sync_read_cursors();
        let map_result = ring.create_user_mapping(file_obj_id, owner_process);

        let user_mem = match map_result {
            Ok(mem) => mem,
            Err(err) => {
                let mut guard = self.active_mapping.lock();
                *guard = MappingState::Unmapped;
                return Err(err);
            }
        };

        let response_payload = user_mem.response();

        let cancelled_mem = {
            let mut guard = self.active_mapping.lock();
            match *guard {
                MappingState::MappingInProgress {
                    cancel_requested: true,
                    ..
                } => {
                    *guard = MappingState::Unmapped;
                    Some(user_mem)
                }
                _ => {
                    *guard = MappingState::Mapped(user_mem);
                    None
                }
            }
        };

        if let Some(mem_to_unmap) = cancelled_mem {
            // Drop outside spinlock at PASSIVE_LEVEL
            drop(mem_to_unmap);
            return Err(RingBufferError::DeviceStateInvalid);
        }

        crate::driver_info!(
            "[ring_buffer::map] Mapped Per-CPU buffers into process address space (Data @ {:#018X}, Status @ {:#018X})",
            response_payload.data_address,
            response_payload.status_address
        );

        Ok(response_payload)
    }

    /// Tears down the active user-mode memory projection and releases the notification event
    /// if and only if `file_object` owns the active mapping session.
    ///
    /// Extracts the `UserModeMemory` under the spinlock and drops it **after** releasing the spinlock
    /// so `MmUnmapLockedPages` and `ObfDereferenceObject` execute at `PASSIVE_LEVEL` in the owning
    /// process's CR3 context.
    ///
    /// # Arguments
    ///
    /// * `file_object` - The `WDFFILEOBJECT` undergoing `EvtFileCleanup`.
    pub(crate) fn teardown_user_mapping_for_file(&self, file_object: WDFFILEOBJECT) {
        let target_file = file_object as usize;
        let current_process = unsafe { IoGetCurrentProcess() } as usize;

        let extracted = {
            let mut guard = self.active_mapping.lock();
            match *guard {
                MappingState::MappingInProgress {
                    file_object: active_file,
                    ref mut cancel_requested,
                    ..
                } if active_file == target_file => {
                    *cancel_requested = true;
                    None
                }
                MappingState::Mapped(ref mem)
                    if mem.file_object() == target_file
                        && mem.owner_process() == current_process =>
                {
                    match core::mem::replace(&mut *guard, MappingState::Unmapped) {
                        MappingState::Mapped(m) => Some(m),
                        _ => None,
                    }
                }
                _ => None,
            }
        };

        // Guard is dropped here, restoring IRQL to PASSIVE_LEVEL before unmapping MDLs!
        if let Some(mem) = extracted {
            drop(mem);
            crate::driver_info!(
                "[ring_buffer::teardown] User memory mapping torn down safely at PASSIVE_LEVEL"
            );
        }
    }

    /// Registers a user-mode Win32 event handle for kernel event notifications.
    ///
    /// References the user-mode event handle in the calling process context and attaches
    /// it to the active mapping session owned by `file_object`. Any previously registered event
    /// is extracted and dropped outside the spinlock at `PASSIVE_LEVEL`.
    ///
    /// # Safety
    /// Caller must ensure `handle` is a valid Win32 synchronization event handle belonging
    /// to the current process context.
    ///
    /// # Arguments
    ///
    /// * `file_object` - Originating `WDFFILEOBJECT` from the IOCTL request.
    /// * `handle` - Win32 event handle to be referenced and signaled.
    ///
    /// # Return values
    ///
    /// * `Ok(())` - Event object referenced and registered successfully.
    /// * `Err(NTSTATUS)` - Object Manager lookup failure, invalid state, or ownership mismatch.
    pub(crate) unsafe fn register_notification_event(
        &self,
        file_object: WDFFILEOBJECT,
        handle: wdk_sys::HANDLE,
    ) -> Result<(), NTSTATUS> {
        let event = unsafe { KernelNotificationEvent::from_handle(handle)? };
        let caller_file = file_object as usize;

        let result = {
            let mut guard = self.active_mapping.lock();
            match *guard {
                MappingState::Mapped(ref mut session) => {
                    if session.file_object() != caller_file {
                        Err((event, STATUS_ACCESS_DENIED))
                    } else {
                        Ok(session.set_notification_event(event))
                    }
                }
                _ => Err((event, RingBufferError::DeviceStateInvalid.to_ntstatus())),
            }
        };

        // Any old or rejected KernelNotificationEvent is dropped here at PASSIVE_LEVEL
        match result {
            Ok(old_event) => {
                drop(old_event);
                crate::driver_info!(
                    "[ring_buffer::event] Kernel notification event registered successfully"
                );
                Ok(())
            }
            Err((rejected_event, status)) => {
                drop(rejected_event);
                Err(status)
            }
        }
    }

    /// Signals the active user-mode reader thread.
    ///
    /// Checks the active session under the spinlock and triggers the registered Win32 event.
    #[inline(always)]
    pub(crate) fn signal_reader(&self) {
        let guard = self.active_mapping.lock();
        if let MappingState::Mapped(ref session) = *guard {
            session.signal_reader();
        }
    }

    /// Writes a telemetry event into the specified CPU core's partition lock-free without spinlocks.
    ///
    /// Loads the active ring buffer atomically and commits the event record into the target CPU partition.
    ///
    /// # Arguments
    ///
    /// * `cpu_id` - Target logical processor index.
    /// * `event_type` - Numeric discriminator for the telemetry event.
    /// * `payload` - Raw serialized byte slice.
    ///
    /// # Return values
    ///
    /// * `Ok(())` - Event successfully committed into the per-CPU circular partition.
    /// * `Err(RingBufferError::DeviceStateInvalid)` - Ring buffer is uninitialized or stopped.
    /// * `Err(RingBufferError::InvalidCpuIndex)` - Target CPU index exceeds active processor count.
    /// * `Err(RingBufferError::DataMemoryAllocationFailed)` - Target core buffer partition is full.
    #[inline(always)]
    #[allow(dead_code)]
    pub(crate) fn write_event(
        &self,
        cpu_id: u32,
        event_type: u16,
        payload: &[u8],
    ) -> Result<(), RingBufferError> {
        let ptr = self.ring_buffer.load(Ordering::Acquire);
        if ptr.is_null() {
            return Err(RingBufferError::DeviceStateInvalid);
        }
        let ring = unsafe { &*ptr };
        ring.write_event(cpu_id, event_type, payload)
    }

    /// Serializes and writes a [`DriverEvent`] into the current processor's partition lock-free.
    ///
    /// Identifies the executing processor core and writes the event directly into its partition.
    ///
    /// # Arguments
    ///
    /// * `event` - Reference to the strongly-typed driver event.
    ///
    /// # Return values
    ///
    /// * `Ok(())` - Driver event serialized and written successfully.
    /// * `Err(RingBufferError::DeviceStateInvalid)` - Ring buffer is uninitialized or stopped.
    /// * `Err(RingBufferError::InvalidCpuIndex)` - Executing CPU index exceeds active processor count.
    /// * `Err(RingBufferError::DataMemoryAllocationFailed)` - Executing core buffer partition is full.
    #[inline(always)]
    pub(crate) fn write_driver_event<E: DriverEvent>(&self, event: &E) -> Result<(), RingBufferError> {
        let ptr = self.ring_buffer.load(Ordering::Acquire);
        if ptr.is_null() {
            return Err(RingBufferError::DeviceStateInvalid);
        }
        let ring = unsafe { &*ptr };
        ring.write_driver_event(event)
    }
}
