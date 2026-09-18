//! RAII lifecycle manager for Object Manager callback registration.

use core::ptr;
use wdk::nt_success;
use wdk_sys::{
    _OB_CALLBACK_REGISTRATION, OB_FLT_REGISTRATION_VERSION, OB_OPERATION_REGISTRATION, PVOID,
    ntddk::{ObRegisterCallbacks, ObUnRegisterCallbacks},
};

use super::error::CallbackError;
use super::operations::Callback;
use crate::foundation::string::init_unicode_string;

/// Maximum number of operations supported in a single stack-allocated registration batch.
const MAX_OPERATIONS: usize = 4;

/// Manages the lifecycle of an active Windows Object Manager registration.
///
/// This structure acts as an RAII guard. When dropped, it automatically unregisters
/// the kernel handle to prevent calling into unloaded memory during driver unload.
pub struct CallbackManager {
    handle: PVOID,
}

impl CallbackManager {
    /// Registers callbacks with the Windows Object Manager.
    ///
    /// This function sets up the required registration structures and submits them
    /// to `ObRegisterCallbacks`. Callbacks remain active until this manager is dropped
    /// or explicitly unregistered.
    ///
    /// # Arguments
    ///
    /// * `altitude` - Null-terminated wide string specifying the filter altitude.
    /// * `callbacks` - Slice of callback definitions to register.
    ///
    /// # Return values
    ///
    /// * `Ok(CallbackManager)` - The initialized guard holding the active registration handle.
    /// * `Err(CallbackError)` - Detailed domain error if registration fails.
    pub fn register(altitude: *const u16, callbacks: &[Callback]) -> Result<Self, CallbackError> {
        if callbacks.is_empty() {
            crate::driver_error!("[callbacks::register] Callback list is empty");
            return Err(CallbackError::EmptyCallbacksList);
        }

        if callbacks.len() > MAX_OPERATIONS {
            crate::driver_error!(
                "[callbacks::register] Requested {} callbacks exceeds max capacity of {}",
                callbacks.len(),
                MAX_OPERATIONS
            );
            return Err(CallbackError::MaxCapacityExceeded {
                max: MAX_OPERATIONS,
                actual: callbacks.len(),
            });
        }

        // Each entry must specify at least one callback routine
        for (index, cb) in callbacks.iter().enumerate() {
            if cb.pre_operation.is_none() && cb.post_operation.is_none() {
                crate::driver_error!(
                    "[callbacks::register] Callback entry at index {index} defines neither pre nor post operation routine"
                );
                return Err(CallbackError::MissingRoutine { index });
            }
        }

        let unicode_altitude = unsafe { init_unicode_string(altitude) };

        let mut raw_operations: [OB_OPERATION_REGISTRATION; MAX_OPERATIONS] =
            unsafe { core::mem::zeroed() };

        for (index, cb) in callbacks.iter().enumerate() {
            raw_operations[index] = OB_OPERATION_REGISTRATION {
                ObjectType: unsafe { cb.kind.as_raw_object_type() },
                Operations: cb.operation.to_raw(),
                PreOperation: cb.pre_operation,
                PostOperation: cb.post_operation,
            };
        }

        let mut registration = _OB_CALLBACK_REGISTRATION {
            Version: OB_FLT_REGISTRATION_VERSION as u16,
            OperationRegistrationCount: callbacks.len() as u16,
            Altitude: unicode_altitude,
            RegistrationContext: ptr::null_mut(),
            OperationRegistration: raw_operations.as_mut_ptr(),
        };

        let mut handle: PVOID = ptr::null_mut();

        // SAFETY: The stack structures and altitude string remain valid for the duration
        // of ObRegisterCallbacks. Windows copies registration data into executive memory.
        let status = unsafe { ObRegisterCallbacks(&mut registration, &mut handle) };
        if !nt_success(status) {
            match status {
                wdk_sys::STATUS_FLT_INSTANCE_ALTITUDE_COLLISION => {
                    crate::driver_error!(
                        "[callbacks::register] Altitude collision with existing filter ({status:#010X})"
                    );
                    return Err(CallbackError::AltitudeCollision { status });
                }
                wdk_sys::STATUS_ACCESS_DENIED => {
                    crate::driver_error!(
                        "[callbacks::register] Access denied ({status:#010X}). Verify driver signature."
                    );
                    return Err(CallbackError::AccessDenied { status });
                }
                wdk_sys::STATUS_INSUFFICIENT_RESOURCES => {
                    crate::driver_error!(
                        "[callbacks::register] Insufficient pool resources ({status:#010X})"
                    );
                    return Err(CallbackError::InsufficientResources { status });
                }
                _ => {
                    crate::driver_error!(
                        "[callbacks::register] ObRegisterCallbacks failed {status:#010X}"
                    );
                    return Err(CallbackError::RegistrationFailed { status });
                }
            }
        }

        if handle.is_null() {
            crate::driver_error!(
                "[callbacks::register] ObRegisterCallbacks returned a null handle"
            );
            return Err(CallbackError::NullHandleReturned);
        }

        crate::driver_info!("[callbacks::register] Callbacks registered successfully");
        Ok(Self { handle })
    }

    /// Reconstructs a `CallbackManager` guard from a previously registered raw handle.
    ///
    /// # Safety
    /// `handle` must be a valid Object Manager registration handle obtained via `into_raw()`.
    pub unsafe fn from_raw(handle: PVOID) -> Self {
        Self { handle }
    }

    /// Consumes the manager guard and returns the raw kernel handle without unregistering.
    pub fn into_raw(mut self) -> PVOID {
        let handle = self.handle;
        self.handle = ptr::null_mut();
        core::mem::forget(self);
        handle
    }

    /// Unregisters the callbacks from the kernel.
    ///
    /// This method can be invoked to disable callbacks on demand. Subsequent calls or
    /// dropping the manager will safely perform no operation.
    pub fn unregister(&mut self) {
        if !self.handle.is_null() {
            // SAFETY: ObUnRegisterCallbacks must be called at IRQL == PASSIVE_LEVEL with a valid handle.
            // Nulling the handle immediately prevents accidental double unregistration.
            unsafe {
                ObUnRegisterCallbacks(self.handle);
            }
            self.handle = ptr::null_mut();
            crate::driver_info!("[callbacks::unregister] Callbacks unregistered successfully");
        }
    }
}

impl Drop for CallbackManager {
    fn drop(&mut self) {
        self.unregister();
    }
}
