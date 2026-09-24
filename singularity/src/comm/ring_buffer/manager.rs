//! Singleton lifecycle manager for the shared memory ring buffer backing pool allocations.

use core::sync::atomic::{AtomicPtr, AtomicU64, Ordering};
use wdk_sys::{
    DISPATCH_LEVEL, PVOID,
    ntddk::{ExAllocatePool2, ExFreePoolWithTag},
};

use crate::{comm::ring_buffer::error::RingBufferError, foundation::ensure_max_irql, wrappers};

/// 4-byte pool tag identifier for ring buffer memory allocations ('QSAR').
const POOL_TAG: u32 = u32::from_ne_bytes(*b"QSAR");
/// Total allocation size of the NonPaged data buffer (4 MB).
const DATA_BUFFER_SIZE: u64 = 4 * 1024 * 1024;
/// Total allocation size of the NonPaged status page buffer (4 KB).
const STATUS_BUFFER_SIZE: u64 = 4 * 1024;

/// Singleton manager for the shared memory ring buffer memory and lifecycle.
pub struct RingBufferManager {
    data_buffer: AtomicPtr<core::ffi::c_void>,
    status_page: AtomicPtr<core::ffi::c_void>,
    write_head: AtomicU64,
    sequence: AtomicU64,
}

impl RingBufferManager {
    /// Creates a new uninitialized `RingBufferManager` instance.
    pub const fn new() -> Self {
        Self {
            data_buffer: AtomicPtr::new(core::ptr::null_mut()),
            status_page: AtomicPtr::new(core::ptr::null_mut()),
            write_head: AtomicU64::new(0),
            sequence: AtomicU64::new(0),
        }
    }

    /// Checks whether the shared memory ring buffer is currently initialized and active.
    ///
    /// # Returns
    ///
    /// `true` if the backing memory buffers are currently allocated, `false` otherwise.
    #[inline(always)]
    pub fn is_active(&self) -> bool {
        !self.data_buffer.load(Ordering::Relaxed).is_null()
    }

    /// Allocates NonPaged pool memory regions for the telemetry ring buffer.
    ///
    /// Validates the current IRQL and allocates both the 4 MB telemetry data buffer and
    /// the 4 KB consumer status page using `ExAllocatePool2`. If the secondary allocation
    /// fails, the first buffer is immediately freed to prevent a kernel pool leak.
    ///
    /// # Return values
    ///
    /// * `Ok(())` - Ring buffer memory allocated successfully.
    /// * `Err(RingBufferError::AlreadyInitialized)` - Ring buffer is already active.
    /// * `Err(RingBufferError::InvalidIrql)` - Current IRQL exceeds `DISPATCH_LEVEL`.
    /// * `Err(RingBufferError::InvalidParameter)` - Size or pool tag is invalid (e.g. zero).
    /// * `Err(RingBufferError::PoolAllocationFailed)` - System memory pool exhaustion.
    pub fn initialize(&self) -> Result<(), RingBufferError> {
        if self.is_active() {
            crate::driver_warn!("[ring_buffer::initialize] Ring buffer is already initialized");
            return Err(RingBufferError::AlreadyInitialized);
        }

        // NonPaged pool allocation is only permitted at or below DISPATCH_LEVEL.
        if let Err(current_irql) = ensure_max_irql(DISPATCH_LEVEL as u8) {
            crate::driver_error!(
                "[ring_buffer::initialize] Invalid IRQL {current_irql} (must be <= DISPATCH_LEVEL)"
            );
            return Err(RingBufferError::InvalidIrql {
                current: current_irql,
                max: DISPATCH_LEVEL as u8,
            });
        }

        let data_buffer = Self::allocate_pool(DATA_BUFFER_SIZE)?;
        let status_page = match Self::allocate_pool(STATUS_BUFFER_SIZE) {
            Ok(ptr) => ptr,
            Err(err) => {
                // SAFETY:
                // `data_buffer` was successfully allocated from NonPaged pool with `POOL_TAG`
                // and has not yet been exposed to any other subsystem, making immediate deallocation safe.
                unsafe {
                    ExFreePoolWithTag(data_buffer, POOL_TAG);
                }
                return Err(err);
            }
        };

        self.data_buffer.store(data_buffer, Ordering::Release);
        self.status_page.store(status_page, Ordering::Release);

        crate::driver_info!(
            "[ring_buffer::initialize] Ring buffer memory initialized successfully"
        );
        Ok(())
    }

    /// Releases all owned kernel pool allocations and nulls the internal pointers.
    ///
    /// Atomically swaps the active buffer pointers with null, ensuring complete idempotency
    /// against duplicate or concurrent teardown invocations. Verifies that the execution context
    /// satisfies `IRQL <= DISPATCH_LEVEL` as mandated by `ExFreePoolWithTag`.
    pub fn cleanup(&self) {
        if let Err(current_irql) = ensure_max_irql(DISPATCH_LEVEL as u8) {
            crate::driver_error!(
                "[ring_buffer::cleanup] Invalid IRQL {current_irql} (ExFreePoolWithTag requires <= DISPATCH_LEVEL)"
            );
            return;
        }

        let data_buffer = self
            .data_buffer
            .swap(core::ptr::null_mut(), Ordering::AcqRel);
        let status_page = self
            .status_page
            .swap(core::ptr::null_mut(), Ordering::AcqRel);

        if !data_buffer.is_null() {
            // SAFETY:
            // The data buffer pointer was allocated from NonPaged pool with POOL_TAG and is
            // guaranteed to be valid and safe to free at <= DISPATCH_LEVEL. Swapping the pointer
            // atomically with null prior to deallocation eliminates dangling references and double-free hazards.
            unsafe {
                ExFreePoolWithTag(data_buffer, POOL_TAG);
            }
        }

        if !status_page.is_null() {
            // SAFETY:
            // The status page pointer was allocated from NonPaged pool with POOL_TAG and is
            // guaranteed to be valid and safe to free at <= DISPATCH_LEVEL. Swapping the pointer
            // atomically with null prior to deallocation eliminates dangling references and double-free hazards.
            unsafe {
                ExFreePoolWithTag(status_page, POOL_TAG);
            }
        }

        if !data_buffer.is_null() || !status_page.is_null() {
            crate::driver_info!("[ring_buffer::cleanup] Ring buffer memory released successfully");
        }
    }

    /// Returns the raw pointer to the NonPaged telemetry data buffer.
    #[inline(always)]
    pub fn data_buffer(&self) -> PVOID {
        self.data_buffer.load(Ordering::Acquire)
    }

    /// Returns the raw pointer to the NonPaged consumer status page.
    #[inline(always)]
    pub fn status_page(&self) -> PVOID {
        self.status_page.load(Ordering::Acquire)
    }

    pub fn push_event() {
        todo!()
    }

    /// Allocates a contiguous NonPaged pool buffer of the specified size.
    ///
    /// # Arguments
    ///
    /// * `pool_size` - Size in bytes to allocate from NonPaged pool memory.
    ///
    /// # Return values
    ///
    /// * `Ok(PVOID)` - Valid, non-null pointer to the allocated kernel pool memory.
    /// * `Err(RingBufferError::InvalidParameter)` - `pool_size` is zero or `POOL_TAG` is invalid.
    /// * `Err(RingBufferError::PoolAllocationFailed)` - System pool memory exhaustion.
    fn allocate_pool(pool_size: u64) -> Result<PVOID, RingBufferError> {
        // Validate buffer size and pool tag to guarantee that invalid parameters are never passed to the allocator.
        if pool_size == 0 || POOL_TAG == 0 {
            crate::driver_error!("[ring_buffer::memory] Invalid buffer size or pool tag parameter");
            return Err(RingBufferError::InvalidParameter);
        }
        let flags = wrappers::PoolFlag::NonPaged | wrappers::PoolFlag::Uninitialized;

        // SAFETY:
        // Calling `ExAllocatePool2` is unsafe because it can cause a kernel bugcheck if called
        // at an IRQL above DISPATCH_LEVEL, if supplied with conflicting or invalid pool flags, or
        // if passed a zero allocation size. This call is guaranteed to be safe because the current IRQL
        // was verified to be at or below DISPATCH_LEVEL prior to allocation, `pool_size` and `POOL_TAG`
        // are explicitly validated to be non-zero, and `flags` contains valid, compatible NonPaged and
        // Uninitialized pool attributes. Furthermore, omitting `RaiseOnFailure` guarantees that memory
        // exhaustion is signaled by returning a null pointer rather than raising an unhandled kernel exception.
        let buffer_handle = unsafe { ExAllocatePool2(flags.into(), pool_size, POOL_TAG) };

        // Because IRQL, size, tag, and flags are verified to be valid, a null return indicates that
        // the kernel memory manager has exhausted available NonPaged pool pages.
        if buffer_handle.is_null() {
            crate::driver_error!(
                "[ring_buffer::memory] ExAllocatePool2 failed: insufficient system resources"
            );
            return Err(RingBufferError::PoolAllocationFailed);
        }

        Ok(buffer_handle)
    }
}
