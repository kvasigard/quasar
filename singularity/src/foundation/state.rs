//! Central driver state and subsystem lifecycle coordination.

use core::sync::atomic::{AtomicBool, Ordering};

/// Represents the global runtime state of the Singularity driver.
///
/// Coordinates initialization milestones and orchestrates safe, sequential
/// teardown and rollback of subsystems during unload or startup failure.
pub struct DriverState {
    device_created: AtomicBool,
    callbacks_registered: AtomicBool,
    ring_buffer: AtomicBool,
    initialized: AtomicBool,
}

impl DriverState {
    /// Creates a new uninitialized driver state instance.
    pub const fn new() -> Self {
        Self {
            device_created: AtomicBool::new(false),
            callbacks_registered: AtomicBool::new(false),
            ring_buffer: AtomicBool::new(false),
            initialized: AtomicBool::new(false),
        }
    }

    /// Records that the control device and symbolic link were successfully created.
    pub fn mark_device_created(&self) {
        self.device_created.store(true, Ordering::Release);
    }

    /// Returns whether the control device has been created.
    pub fn is_device_created(&self) -> bool {
        self.device_created.load(Ordering::Acquire)
    }

    /// Records that the shared memory ring buffer was successfully created.
    pub fn mark_ring_created(&self) {
        self.ring_buffer.store(true, Ordering::Release);
    }

    /// Returns whether the shared memory ring buffer has been created.
    pub fn is_ring_created(&self) -> bool {
        self.ring_buffer.load(Ordering::Acquire)
    }

    /// Records that Object Manager callbacks have been registered.
    pub fn mark_callbacks_registered(&self) {
        self.callbacks_registered.store(true, Ordering::Release);
    }

    /// Returns whether Object Manager callbacks are currently active.
    pub fn is_callbacks_registered(&self) -> bool {
        self.callbacks_registered.load(Ordering::Acquire)
    }

    /// Marks the driver as fully initialized.
    pub fn mark_initialized(&self) {
        self.initialized.store(true, Ordering::Release);
    }

    /// Checks whether the driver subsystems are fully initialized and active.
    pub fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::Acquire)
    }

    /// Performs safe, sequential cleanup of all active subsystems in reverse order.
    ///
    /// Subsystems are torn down in strict reverse dependency order: Object Manager callbacks
    /// are detached first to halt incoming telemetry event production, followed by shared memory
    /// ring buffer deallocation to ensure no concurrent writes can trigger a Use-After-Free.
    /// Safe to invoke multiple times; state transitions and underlying manager teardown are idempotent.
    pub fn cleanup_all(&self) {
        self.initialized.store(false, Ordering::Release);

        // Unregister callbacks first: halts telemetry producer routines (on_pre_process_operation).
        if self.callbacks_registered.swap(false, Ordering::AcqRel) {
            crate::domains::callbacks::cleanup();
        }

        // Tear down ring buffer second: safe from concurrent writes since callbacks are detached.
        if self.ring_buffer.swap(false, Ordering::AcqRel) {
            crate::comm::ring_buffer::cleanup();
        }

        // Reset control device creation flag.
        self.device_created.store(false, Ordering::Release);
    }
}

/// Global singleton driver state instance.
pub static DRIVER_STATE: DriverState = DriverState::new();
