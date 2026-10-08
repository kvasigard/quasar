//! Shared memory ring buffer domain for kernel-to-user telemetry streaming.

mod error;
mod manager;
mod mdl;
mod notifier;
mod queue;
mod session;

pub(crate) use error::RingBufferError;
pub(crate) use manager::RingBufferManager;

use shared::ioctl::PerCpuMapResponse;
use shared::ring_buffer::DriverEvent;
use wdk_sys::NTSTATUS;

/// Global singleton manager for the shared memory ring buffer.
pub(crate) static RING_BUFFER_MANAGER: RingBufferManager = RingBufferManager::new();

/// Checks whether the shared memory ring buffer is currently active.
///
/// Queries the underlying manager to determine if backing partitions are resident.
///
/// # Return values
///
/// * `true` - Ring buffer backing memory is allocated and ready.
/// * `false` - Ring buffer is uninitialized or torn down.
#[inline(always)]
pub(crate) fn is_active() -> bool {
    RING_BUFFER_MANAGER.is_active()
}

/// Initializes and allocates the shared memory ring buffer.
///
/// Allocates contiguous NonPaged pool partitions across all detected CPU cores.
///
/// # Return values
///
/// * `Ok(())` - Backing memory partitions allocated and published.
/// * `Err(RingBufferError::AlreadyInitialized)` - Ring buffer is already active.
/// * `Err(RingBufferError)` - Pool allocation, IRQL violation, or alignment error.
#[inline(always)]
pub(crate) fn initialize() -> Result<(), RingBufferError> {
    RING_BUFFER_MANAGER.initialize()
}

/// Releases all ring buffer memory and teardown resources.
///
/// Cleans up any user mapping projection and deallocates backing NonPaged pool memory.
#[inline(always)]
pub(crate) fn cleanup() {
    RING_BUFFER_MANAGER.cleanup();
}

/// Projects the contiguous per-CPU shared memory pools into the calling process address space.
///
/// Maps data (read-only) and status (read-write) partitions into the calling user process.
///
/// # Return values
///
/// * `Ok(PerCpuMapResponse)` - Response structure containing mapped user-mode base addresses and geometry.
/// * `Err(RingBufferError::AlreadyMapped)` - An active user-mode mapping session is already established.
/// * `Err(RingBufferError::DeviceStateInvalid)` - Ring buffer backing memory is uninitialized.
/// * `Err(RingBufferError)` - Mapping or MDL allocation failure.
#[inline(always)]
pub(crate) fn create_user_mapping() -> Result<PerCpuMapResponse, RingBufferError> {
    RING_BUFFER_MANAGER.create_user_mapping()
}

/// Tears down the active user-mode memory projection and releases the notification event.
///
/// Safely unmaps locked user-mode pages and releases referenced event synchronization objects.
#[inline(always)]
pub(crate) fn teardown_user_mapping() {
    RING_BUFFER_MANAGER.teardown_user_mapping();
}

/// Registers a user-mode Win32 event handle for kernel event notifications.
///
/// References the event handle within the calling process context for reader notifications.
///
/// # Safety
/// Caller must ensure `handle` is a valid Win32 synchronization event handle belonging
/// to the current process context.
///
/// # Arguments
///
/// * `handle` - Win32 event handle to be referenced and signaled.
///
/// # Return values
///
/// * `Ok(())` - Event object referenced and registered successfully.
/// * `Err(NTSTATUS)` - Object Manager lookup failure or invalid handle status.
#[inline(always)]
pub(crate) unsafe fn register_notification_event(handle: wdk_sys::HANDLE) -> Result<(), NTSTATUS> {
    unsafe { RING_BUFFER_MANAGER.register_notification_event(handle) }
}

/// Signals the active user-mode reader thread.
///
/// Triggers the registered Win32 event to wake the user-mode telemetry consumer loop.
#[inline(always)]
pub(crate) fn signal_reader() {
    RING_BUFFER_MANAGER.signal_reader();
}

/// Writes a telemetry event into the specified CPU core's partition.
///
/// Commits an event record into the target processor's circular buffer partition lock-free.
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
pub(crate) fn write_event(cpu_id: u32, event_type: u16, payload: &[u8]) -> Result<(), RingBufferError> {
    RING_BUFFER_MANAGER.write_event(cpu_id, event_type, payload)
}

/// Serializes and writes a [`DriverEvent`] into the current processor's partition.
///
/// Commits a strongly-typed driver event into the executing CPU core's partition lock-free.
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
pub(crate) fn write_driver_event<E: DriverEvent>(event: &E) -> Result<(), RingBufferError> {
    RING_BUFFER_MANAGER.write_driver_event(event)
}
