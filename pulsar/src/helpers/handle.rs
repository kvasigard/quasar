//! Safe RAII wrappers for Win32 synchronization and file handles.

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};

/// Safe RAII wrapper around a Win32 object handle (`HANDLE`).
///
/// Automatically calls [`CloseHandle`] when dropped, preventing resource leaks.
#[derive(Debug)]
pub struct SafeHandle(HANDLE);

unsafe impl Send for SafeHandle {}
unsafe impl Sync for SafeHandle {}

impl SafeHandle {
    /// Creates a new `SafeHandle` from a raw Win32 handle.
    ///
    /// # Arguments
    ///
    /// * `handle` - Raw Win32 handle.
    ///
    /// # Returns
    ///
    /// `Some(SafeHandle)` if the handle is valid and non-null, or `None` if `INVALID_HANDLE_VALUE` or null.
    pub fn new(handle: HANDLE) -> Option<Self> {
        if handle == INVALID_HANDLE_VALUE || handle.is_null() {
            None
        } else {
            Some(Self(handle))
        }
    }

    /// Returns the underlying raw Win32 `HANDLE`.
    ///
    /// # Returns
    ///
    /// The inner Win32 handle value.
    #[inline(always)]
    pub fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for SafeHandle {
    fn drop(&mut self) {
        if self.0 != INVALID_HANDLE_VALUE && !self.0.is_null() {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_safe_handle_invalid_and_null() {
        assert!(SafeHandle::new(INVALID_HANDLE_VALUE).is_none());
        assert!(SafeHandle::new(core::ptr::null_mut()).is_none());
    }
}
