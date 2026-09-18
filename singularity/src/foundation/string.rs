//! Safe wrappers and utilities for Windows kernel `UNICODE_STRING` handling.

use core::mem::MaybeUninit;
use wdk_sys::{ntddk::RtlInitUnicodeString, UNICODE_STRING};

/// Initializes a `UNICODE_STRING` from a null-terminated UTF-16 wide string pointer.
///
/// # Safety
///
/// The caller must ensure that `wide_buffer` points to a valid null-terminated slice of
/// 16-bit wide characters (e.g. created with `windows_sys::w!`).
#[inline]
pub unsafe fn init_unicode_string(wide_buffer: *const u16) -> UNICODE_STRING {
    let mut string_uninit = MaybeUninit::<UNICODE_STRING>::uninit();
    unsafe {
        RtlInitUnicodeString(string_uninit.as_mut_ptr(), wide_buffer);
        string_uninit.assume_init()
    }
}
