//! Object Manager callback registration and lifecycle management domain.

pub(crate) mod error;
pub(crate) mod filters;
pub(crate) mod handlers;
pub(crate) mod manager;
pub(crate) mod operations;

pub(crate) use error::CallbackError;
pub(crate) use handlers::on_pre_process_operation;
pub(crate) use manager::CallbackManager;
pub(crate) use operations::{Callback, CallbackType, OperationType, DEFAULT_ALTITUDE};

/// Global singleton manager for Object Manager callbacks.
pub(crate) static CALLBACK_MANAGER: CallbackManager = CallbackManager::new();

/// Checks whether Object Manager callbacks are currently active.
///
/// Queries whether a valid kernel registration cookie is held.
///
/// # Return values
///
/// * `true` - Callbacks are registered with the Windows Object Manager.
/// * `false` - Callbacks are uninitialized or unregistered.
#[inline(always)]
pub(crate) fn is_active() -> bool {
    CALLBACK_MANAGER.is_active()
}

/// Initializes and registers all kernel callbacks during driver startup.
///
/// Submits process handle monitoring hooks at the default filter altitude.
///
/// # Return values
///
/// * `Ok(())` - Callbacks successfully registered.
/// * `Err(CallbackError::AlreadyInitialized)` - Callbacks are already active.
/// * `Err(CallbackError)` - Registration failure or access denial.
pub(crate) fn initialize() -> Result<(), CallbackError> {
    crate::driver_debug!("[callbacks::initialize] Initializing Object Manager callbacks");
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

    unsafe { CALLBACK_MANAGER.register(DEFAULT_ALTITUDE, &callbacks) }
}

/// Unregisters all kernel callbacks during driver unload or initialization rollback.
///
/// Detaches the registered callbacks from the Object Manager at `PASSIVE_LEVEL`.
#[inline(always)]
pub(crate) fn cleanup() {
    CALLBACK_MANAGER.unregister();
}
