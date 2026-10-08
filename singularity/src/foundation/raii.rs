//! Generic RAII guards for Windows Kernel object references and synchronization.

use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};
use wdk_sys::{
    KIRQL, KSPIN_LOCK, PEPROCESS,
    ntddk::{KeAcquireSpinLockRaiseToDpc, KeReleaseSpinLock, ObfDereferenceObject},
};

/// An RAII guard for safely managing the lifecycle of an `EPROCESS` reference.
///
/// Ensures that kernel object references acquired via lookup functions (such as
/// `PsLookupProcessByProcessId`) are properly decremented when the guard leaves scope,
/// preventing kernel memory leaks.
pub(crate) struct EprocessGuard(pub(crate) PEPROCESS);

impl EprocessGuard {
    /// Creates a new guard wrapping a valid `PEPROCESS` reference.
    ///
    /// Takes ownership of an already referenced process pointer.
    ///
    /// # Arguments
    ///
    /// * `process` - Valid referenced kernel `PEPROCESS` pointer.
    ///
    /// # Return values
    ///
    /// * `Self` - RAII guard wrapping the process object.
    pub(crate) fn new(process: PEPROCESS) -> Self {
        Self(process)
    }

    /// Returns the underlying raw `PEPROCESS` pointer.
    ///
    /// Provides access to the referenced kernel pointer.
    ///
    /// # Return values
    ///
    /// * `PEPROCESS` - Underlying pointer to the NT executive process object.
    pub(crate) fn as_ptr(&self) -> PEPROCESS {
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

/// A kernel synchronization primitive that integrates with Windows IRQL rules.
///
/// Wraps the native Windows NT executive [`KSPIN_LOCK`]. When a thread acquires
/// the lock, the driver invokes `KeAcquireSpinLockRaiseToDpc`. This raises the
/// processor's IRQL to `DISPATCH_LEVEL`, disabling thread preemption on that CPU core.
///
/// # Compile-time Const Initialization
/// Initialized with `UnsafeCell::new(0)`, allowing safe static initialization in a `const fn`.
pub(crate) struct KernelSpinLock<T> {
    lock: UnsafeCell<KSPIN_LOCK>,
    data: UnsafeCell<T>,
}

unsafe impl<T: Send> Sync for KernelSpinLock<T> {}
unsafe impl<T: Send> Send for KernelSpinLock<T> {}

impl<T> KernelSpinLock<T> {
    /// Constructs a new kernel spinlock wrapping the supplied value.
    ///
    /// Initializes the underlying `KSPIN_LOCK` word to 0 in a const context.
    ///
    /// # Arguments
    ///
    /// * `data` - Initial value protected by the spinlock.
    ///
    /// # Return values
    ///
    /// * `Self` - Initialized spinlock primitive.
    pub(crate) const fn new(data: T) -> Self {
        Self {
            lock: UnsafeCell::new(0),
            data: UnsafeCell::new(data),
        }
    }

    /// Acquires the lock and raises the processor IRQL to `DISPATCH_LEVEL`.
    ///
    /// Returns an RAII guard that provides exclusive mutable access to the protected data.
    /// When the guard goes out of scope, its destructor restores the original processor IRQL.
    ///
    /// # Return values
    ///
    /// * `KernelSpinLockGuard<'_, T>` - RAII lock guard providing mutable access.
    pub(crate) fn lock(&self) -> KernelSpinLockGuard<'_, T> {
        let old_irql = unsafe { KeAcquireSpinLockRaiseToDpc(self.lock.get()) };
        KernelSpinLockGuard {
            lock: self.lock.get(),
            old_irql,
            data: unsafe { &mut *self.data.get() },
        }
    }
}

/// An RAII guard that holds a kernel spinlock and manages IRQL restoration.
pub(crate) struct KernelSpinLockGuard<'a, T> {
    lock: *mut KSPIN_LOCK,
    old_irql: KIRQL,
    data: &'a mut T,
}

impl<T> Deref for KernelSpinLockGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        self.data
    }
}

impl<T> DerefMut for KernelSpinLockGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.data
    }
}

impl<T> Drop for KernelSpinLockGuard<'_, T> {
    fn drop(&mut self) {
        unsafe {
            KeReleaseSpinLock(self.lock, self.old_irql);
        }
    }
}
