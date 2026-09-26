//! Shared memory ring buffer domain for kernel-to-user telemetry streaming.

mod error;
mod manager;
mod notifier;
mod queue;

pub use error::RingBufferError;
pub use manager::RingBufferManager;

/// Global singleton manager for the shared memory ring buffer.
pub static RING_BUFFER_MANAGER: RingBufferManager = RingBufferManager::new();

/// Checks whether the shared memory ring buffer is currently active.
#[inline(always)]
pub fn is_active() -> bool {
    RING_BUFFER_MANAGER.is_active()
}

/// Initializes and allocates the shared memory ring buffer.
///
/// # Return values
///
/// * `Ok(())` - Ring buffer successfully initialized.
/// * `Err(RingBufferError)` - Initialization failure.
#[inline(always)]
pub fn initialize() -> Result<(), RingBufferError> {
    RING_BUFFER_MANAGER.initialize()
}

/// Releases all ring buffer memory and teardown resources.
#[inline(always)]
pub fn cleanup() {
    RING_BUFFER_MANAGER.cleanup();
}

/// Enqueues a driver telemetry event into the active shared memory ring buffer.
///
/// Operates with zero heap allocations and is safe to call from arbitrary IRQLs up to `DISPATCH_LEVEL`.
///
/// # Return values
///
/// * `Ok(())` - Event successfully written and committed.
/// * `Err(RingBufferError::NotInitialized)` - Ring buffer is inactive.
/// * `Err(RingBufferError::BufferFull)` - Ring buffer capacity exhausted; dropped counter incremented.
/// * `Err(RingBufferError::InvalidParameter)` - Frame size exceeds buffer capacity.
#[inline(always)]
pub fn push_event(event: &impl shared::ring_buffer::DriverEvent) -> Result<(), RingBufferError> {
    RING_BUFFER_MANAGER.push_event(event)
}
