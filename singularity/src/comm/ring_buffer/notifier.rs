//! RAII wrapper for referenced Windows Kernel Event objects (`PKEVENT`).

use core::ffi::c_void;
use wdk_sys::{
    NTSTATUS,
    ntddk::{KeSetEvent, ObReferenceObjectByHandle, ObfDereferenceObject},
};

/// RAII wrapper for a referenced Windows kernel event object (`PKEVENT`).
///
/// Encapsulates a kernel `KEVENT` referenced via [`ObReferenceObjectByHandle`].
/// When the user-mode client terminates or closes its device handle, the destructor
/// automatically invokes [`ObfDereferenceObject`], ensuring that kernel object
/// reference counts remain balanced without memory or handle leaks.
pub(crate) struct KernelNotificationEvent {
    raw_event: *mut c_void,
}

unsafe impl Send for KernelNotificationEvent {}
unsafe impl Sync for KernelNotificationEvent {}

impl KernelNotificationEvent {
    /// References a Win32 event handle created in user space.
    ///
    /// Resolves the user-mode handle into an opaque kernel `KEVENT` object pointer and increments
    /// its reference count.
    ///
    /// # Safety
    /// Must be called while executing in the virtual memory context of the target process
    /// that created or inherited the Win32 event handle.
    ///
    /// # Arguments
    ///
    /// * `handle` - Win32 event handle created by the telemetry reader process.
    ///
    /// # Return values
    ///
    /// * `Ok(Self)` - Referenced kernel event wrapper successfully created.
    /// * `Err(NTSTATUS)` - Object lookup failed or handle is invalid.
    pub(crate) unsafe fn from_handle(handle: wdk_sys::HANDLE) -> Result<Self, NTSTATUS> {
        let mut object: *mut c_void = core::ptr::null_mut();
        let status = unsafe {
            ObReferenceObjectByHandle(
                handle,
                0x0002, // EVENT_MODIFY_STATE
                *wdk_sys::ExEventObjectType,
                wdk_sys::_MODE::UserMode as wdk_sys::KPROCESSOR_MODE,
                &raw mut object,
                core::ptr::null_mut(),
            )
        };

        if !wdk::nt_success(status) {
            return Err(status);
        }

        Ok(Self { raw_event: object })
    }

    /// Signals the event to wake up waiting user-mode consumer threads.
    ///
    /// Invokes `KeSetEvent` with `IO_NO_INCREMENT`.
    #[inline(always)]
    pub(crate) fn set(&self) {
        unsafe {
            KeSetEvent(self.raw_event.cast(), 0, 0);
        }
    }
}

impl Drop for KernelNotificationEvent {
    fn drop(&mut self) {
        if !self.raw_event.is_null() {
            unsafe {
                ObfDereferenceObject(self.raw_event);
            }
        }
    }
}
