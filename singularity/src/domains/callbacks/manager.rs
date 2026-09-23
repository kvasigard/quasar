//! Singleton lifecycle manager for Object Manager callback registration.

use core::ptr;
use core::sync::atomic::{AtomicPtr, Ordering};
use wdk::nt_success;
use wdk_sys::{
    OB_FLT_REGISTRATION_VERSION, OB_OPERATION_REGISTRATION, PASSIVE_LEVEL, PVOID,
    _OB_CALLBACK_REGISTRATION,
    ntddk::{ObRegisterCallbacks, ObUnRegisterCallbacks},
};

use super::error::CallbackError;
use super::operations::Callback;
use crate::foundation::ensure_max_irql;
use crate::foundation::string::init_unicode_string;

/// Maximum number of operations supported in a single stack-allocated registration batch.
const MAX_OPERATIONS: usize = 4;

/// Singleton manager for Windows Object Manager callback registration.
///
/// Encapsulates the kernel registration cookie within an atomic pointer, coordinating
/// thread-safe registration and idempotent unregistration during driver unload or rollback.
pub struct CallbackManager {
    handle: AtomicPtr<core::ffi::c_void>,
}

impl CallbackManager {
    /// Creates a new uninitialized `CallbackManager` instance.
    pub const fn new() -> Self {
        Self {
            handle: AtomicPtr::new(ptr::null_mut()),
        }
    }

    /// Checks whether Object Manager callbacks are currently active.
    ///
    /// # Returns
    ///
    /// `true` if callbacks are currently registered with the kernel, `false` otherwise.
    pub fn is_active(&self) -> bool {
        !self.handle.load(Ordering::Relaxed).is_null()
    }

    /// Registers callbacks with the Windows Object Manager.
    ///
    /// Configures the callback registration structures and submits them to `ObRegisterCallbacks`
    /// at `PASSIVE_LEVEL`. On success, stores the opaque kernel handle atomically.
    ///
    /// # Arguments
    ///
    /// * `altitude` - Null-terminated wide string specifying the filter altitude.
    /// * `callbacks` - Slice of callback definitions to register.
    ///
    /// # Return values
    ///
    /// * `Ok(())` - Callbacks registered successfully.
    /// * `Err(CallbackError::AlreadyInitialized)` - Callbacks are already active.
    /// * `Err(CallbackError::EmptyCallbacksList)` - Supplied slice contains zero callbacks.
    /// * `Err(CallbackError::MaxCapacityExceeded)` - Number of callbacks exceeds internal limit.
    /// * `Err(CallbackError::MissingRoutine)` - Callback defines neither pre- nor post-operation routine.
    /// * `Err(CallbackError)` - Kernel registration failure or access denial.
    pub fn register(&self, altitude: *const u16, callbacks: &[Callback]) -> Result<(), CallbackError> {
        if self.is_active() {
            crate::driver_warn!("[callbacks::register] Callbacks are already initialized");
            return Err(CallbackError::AlreadyInitialized);
        }

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

        // SAFETY:
        // Calling `ObRegisterCallbacks` is safe because the stack-allocated registration arrays
        // and unicode altitude string remain valid throughout the synchronous call duration, and
        // the Windows kernel copies all registration data into internal executive memory before returning.
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

        self.handle.store(handle, Ordering::Release);
        crate::driver_info!("[callbacks::register] Callbacks registered successfully");
        Ok(())
    }

    /// Unregisters the callbacks from the Windows Object Manager.
    ///
    /// Atomically swaps the active registration handle with null, ensuring complete idempotency
    /// against duplicate or concurrent teardown invocations. Verifies that the execution context
    /// satisfies `IRQL == PASSIVE_LEVEL` as mandated by `ObUnRegisterCallbacks`.
    pub fn unregister(&self) {
        if let Err(current_irql) = ensure_max_irql(PASSIVE_LEVEL as u8) {
            crate::driver_error!(
                "[callbacks::unregister] Invalid IRQL {current_irql} (ObUnRegisterCallbacks requires PASSIVE_LEVEL)"
            );
            return;
        }

        let handle = self.handle.swap(ptr::null_mut(), Ordering::AcqRel);
        if !handle.is_null() {
            // SAFETY:
            // Calling `ObUnRegisterCallbacks` is safe because the handle was verified to be non-null,
            // was previously returned by a successful `ObRegisterCallbacks` call, and the processor
            // is confirmed to execute at PASSIVE_LEVEL. Swapping the handle atomically with null prior
            // to unregistration prevents race conditions and eliminates double-unregistration hazards.
            unsafe {
                ObUnRegisterCallbacks(handle);
            }
            crate::driver_info!("[callbacks::unregister] Callbacks unregistered successfully");
        }
    }
}
