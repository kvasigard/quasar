//! Generic RAII guards for Windows Kernel object references.

use core::ops::Deref;
use wdk_sys::{ntddk::ObfDereferenceObject, PEPROCESS};

/// An RAII guard for safely managing the lifecycle of an `EPROCESS` reference.
///
/// Ensures that kernel object references acquired via lookup functions (such as
/// `PsLookupProcessByProcessId`) are properly decremented when the guard leaves scope,
/// preventing kernel memory leaks.
pub struct EprocessGuard(pub PEPROCESS);

impl EprocessGuard {
    /// Creates a new guard wrapping a valid `PEPROCESS` reference.
    pub fn new(process: PEPROCESS) -> Self {
        Self(process)
    }

    /// Returns the underlying raw `PEPROCESS` pointer.
    pub fn as_ptr(&self) -> PEPROCESS {
        self.0
    }
}

impl Deref for EprocessGuard {
    type Target = PEPROCESS;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Drop for EprocessGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: The internal pointer is valid as it was populated by a lookup function
            // that incremented the object reference count.
            unsafe {
                ObfDereferenceObject(self.0 as _);
            }
            self.0 = core::ptr::null_mut();
        }
    }
}
