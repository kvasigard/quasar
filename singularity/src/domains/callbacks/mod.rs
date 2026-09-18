//! Object Manager callback registration and lifecycle management domain.

pub mod error;
pub mod handlers;
pub mod manager;
pub mod operations;

pub use error::CallbackError;
pub use handlers::{
    on_pre_process_operation, CALLBACK_GATES, GATE_PROCESS_PROTECTION, GATE_THREAD_PROTECTION,
};
pub use manager::CallbackManager;
pub use operations::{
    Callback, CallbackType, OperationType, PostOperationCallbackFn,
    PreOperationCallbackFn, DEFAULT_ALTITUDE,
};

use core::sync::atomic::{AtomicPtr, Ordering};

/// Active Object Manager registration handle stored as an atomic pointer.
static ACTIVE_CALLBACK_HANDLE: AtomicPtr<core::ffi::c_void> =
    AtomicPtr::new(core::ptr::null_mut());

/// Checks whether Object Manager callbacks are currently active.
pub fn is_active() -> bool {
    !ACTIVE_CALLBACK_HANDLE.load(Ordering::Relaxed).is_null()
}

/// Initializes and registers all kernel callbacks during driver startup.
pub fn initialize() -> Result<(), CallbackError> {
    if is_active() {
        crate::driver_warn!("[callbacks::initialize] Callbacks are already initialized");
        return Err(CallbackError::AlreadyInitialized);
    }

    let callbacks = [Callback::new(
        CallbackType::Process,
        OperationType::All,
        Some(on_pre_process_operation),
        None,
    )];

    let manager = CallbackManager::register(DEFAULT_ALTITUDE, &callbacks)?;
    ACTIVE_CALLBACK_HANDLE.store(manager.into_raw(), Ordering::Release);
    Ok(())
}

/// Unregisters all kernel callbacks during driver unload or initialization rollback.
pub fn cleanup() {
    let handle = ACTIVE_CALLBACK_HANDLE.swap(core::ptr::null_mut(), Ordering::AcqRel);
    if !handle.is_null() {
        // SAFETY: Reconstructing the CallbackManager RAII guard ensures safe, single-point unregistration.
        let mut manager = unsafe { CallbackManager::from_raw(handle) };
        manager.unregister();
    }
}
