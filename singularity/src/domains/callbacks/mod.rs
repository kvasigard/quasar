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

/// Global singleton manager for Object Manager callbacks.
pub static CALLBACK_MANAGER: CallbackManager = CallbackManager::new();

/// Checks whether Object Manager callbacks are currently active.
#[inline(always)]
pub fn is_active() -> bool {
    CALLBACK_MANAGER.is_active()
}

/// Initializes and registers all kernel callbacks during driver startup.
///
/// # Return values
///
/// * `Ok(())` - Callbacks successfully registered.
/// * `Err(CallbackError)` - Registration failure.
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

    CALLBACK_MANAGER.register(DEFAULT_ALTITUDE, &callbacks)
}

/// Unregisters all kernel callbacks during driver unload or initialization rollback.
#[inline(always)]
pub fn cleanup() {
    CALLBACK_MANAGER.unregister();
}
