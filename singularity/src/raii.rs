use wdk_sys::{PEPROCESS, ntddk::ObfDereferenceObject};

/// An RAII guard for safely managing the lifecycle of an `EPROCESS` reference.
///
/// This structure ensures that kernel object references acquired via lookup functions
/// are properly decremented when the guard goes out of scope, preventing critical
/// memory leaks in the Windows kernel.
pub struct EprocessGuard(pub PEPROCESS);

impl Drop for EprocessGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: The internal pointer is guaranteed to be valid as it was
            // successfully populated by a kernel API that increments the reference count.
            unsafe {
                ObfDereferenceObject(self.0 as _);
            }
        }
    }
}
