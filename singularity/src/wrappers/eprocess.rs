use core::ffi::CStr;
use core::ptr::NonNull;
use wdk_sys::{
    HANDLE, NTSTATUS, PEPROCESS, PUNICODE_STRING,
    ntddk::{IoGetCurrentProcess, PsGetCurrentProcessId, PsGetProcessId, SeLocateProcessImageName},
};

// PsGetProcessImageFileName is exported by ntoskrnl.exe, but not exposed in wdk-sys headers.
unsafe extern "system" {
    pub fn PsGetProcessImageFileName(Process: PEPROCESS) -> *const i8;
}

/// A zero-cost, non-owning handle to an active Windows EPROCESS.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Eprocess {
    raw: NonNull<wdk_sys::_EPROCESS>,
}

impl Eprocess {
    /// Creates a wrapper from a raw `PEPROCESS` pointer.
    ///
    /// Validates that the supplied pointer is non-null before constructing the wrapper.
    ///
    /// # Safety
    /// The caller must ensure `ptr` is non-null and points to an object that
    /// remains valid for the duration of the wrapper's usage.
    ///
    /// # Arguments
    ///
    /// * `ptr` - Raw kernel `PEPROCESS` pointer.
    ///
    /// # Return values
    ///
    /// * `Some(Self)` - Valid non-null process wrapper.
    /// * `None` - Supplied pointer was null.
    #[inline]
    pub(crate) unsafe fn from_raw(ptr: PEPROCESS) -> Option<Self> {
        NonNull::new(ptr as *mut wdk_sys::_EPROCESS).map(|raw| Self { raw })
    }

    /// Returns the `Eprocess` for the current execution context (the caller).
    ///
    /// Retrieves the current process pointer using `IoGetCurrentProcess`.
    ///
    /// # Return values
    ///
    /// * `Self` - Non-null process wrapper for the calling thread's process.
    #[inline]
    pub(crate) fn current() -> Self {
        let ptr = unsafe { IoGetCurrentProcess() };
        // SAFETY: IoGetCurrentProcess() is guaranteed never to return NULL.
        unsafe {
            Self {
                raw: NonNull::new_unchecked(ptr as *mut _),
            }
        }
    }

    /// Returns the PID for this process instance.
    ///
    /// Invokes `PsGetProcessId` on the wrapped process object.
    ///
    /// # Return values
    ///
    /// * `usize` - Numerical Process ID.
    #[inline]
    pub(crate) fn pid(&self) -> usize {
        let handle: HANDLE = unsafe { PsGetProcessId(self.as_raw()) };
        handle as usize
    }

    /// Returns the PID of the current execution context.
    ///
    /// Invokes `PsGetCurrentProcessId`.
    ///
    /// # Return values
    ///
    /// * `usize` - Current executing Process ID.
    #[inline]
    #[allow(dead_code)]
    pub(crate) fn current_pid() -> usize {
        let handle: HANDLE = unsafe { PsGetCurrentProcessId() };
        handle as usize
    }

    /// Returns the 15-character truncated short image name (e.g., "lsass.exe").
    ///
    /// Reads from `EPROCESS::ImageFileName` which is limited to 15 characters plus null terminator.
    ///
    /// # Return values
    ///
    /// * `&CStr` - Null-terminated ASCII image file name slice.
    #[inline]
    pub(crate) fn short_name(&self) -> &CStr {
        unsafe {
            let name_ptr = PsGetProcessImageFileName(self.as_raw());
            if name_ptr.is_null() {
                c""
            } else {
                CStr::from_ptr(name_ptr)
            }
        }
    }

    /// Retrieves the full NT path of the process executable (e.g. `\Device\HarddiskVolume3\...`).
    ///
    /// Queries `SeLocateProcessImageName` to resolve the full NT image path.
    /// The caller must free the resulting `UNICODE_STRING` buffer using `ExFreePool`.
    ///
    /// # Return values
    ///
    /// * `Ok(*mut wdk_sys::_UNICODE_STRING)` - Allocated unicode string containing full image path.
    /// * `Err(NTSTATUS)` - Query failed or image path unresolvable.
    #[allow(dead_code)]
    pub(crate) fn full_image_path(&self) -> Result<*mut wdk_sys::_UNICODE_STRING, NTSTATUS> {
        let mut unicode_str_ptr: PUNICODE_STRING = core::ptr::null_mut();
        let status = unsafe {
            SeLocateProcessImageName(self.as_raw(), &mut unicode_str_ptr as *mut PUNICODE_STRING)
        };

        if status >= 0 && !unicode_str_ptr.is_null() {
            Ok(unicode_str_ptr)
        } else {
            Err(status)
        }
    }

    /// Returns the raw `PEPROCESS` pointer.
    ///
    /// # Return values
    ///
    /// * `PEPROCESS` - Underlying raw kernel process pointer.
    #[inline]
    pub(crate) fn as_raw(&self) -> PEPROCESS {
        self.raw.as_ptr() as PEPROCESS
    }
}
