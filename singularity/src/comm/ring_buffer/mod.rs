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
