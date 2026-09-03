//! RAII wrapper and IOCTL dispatch client for the Singularity KMDF kernel driver.

use std::ffi::c_void;
use std::ptr;

use super::error::DriverError;
use shared::ioctl::IoctlMessage;
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows_sys::Win32::System::IO::DeviceIoControl;

/// Safe RAII handle to the `\Device\SingularityDevice` kernel device object.
pub struct Singularity(HANDLE);

impl Drop for Singularity {
    fn drop(&mut self) {
        log::trace!(target: "kmdf", "Dropping Singularity KMDF handle");
        if self.0 != INVALID_HANDLE_VALUE {
            // SAFETY: The handle is guaranteed valid or INVALID_HANDLE_VALUE.
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

impl Singularity {
    /// Acquires a handle to interact with the KMDF driver via `CreateFileW`.
    ///
    /// # Returns
    ///
    /// An initialized `Singularity` client handle on success, or an [`DriverError`] on failure.
    ///
    /// # Errors
    ///
    /// Returns [`DriverError::DeviceConnectFailed`] if the device file cannot be opened (e.g. driver not loaded).
    pub fn connect() -> Result<Self, DriverError> {
        let device_path = windows_sys::w!("\\\\.\\SingularityDevice");

        // SAFETY: Device path is built to guarantee proper null-termination via the `w!` macro.
        // Access rights are restricted to the minimum required.
        let handle = unsafe {
            CreateFileW(
                device_path,
                0, // 0 access is sufficient for many IOCTLs depending on device ACLs
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                ptr::null(),
                OPEN_EXISTING,
                0,
                ptr::null_mut(),
            )
        };

        if handle == INVALID_HANDLE_VALUE {
            let err = unsafe { GetLastError() };
            return Err(DriverError::DeviceConnectFailed {
                device: "\\\\.\\SingularityDevice",
                code: err,
                message: crate::error::format_win32_error_message(err),
            });
        }

        log::debug!(target: "kmdf", "Successfully acquired handle to Singularity KMDF driver.");

        Ok(Self(handle))
    }

    /// Dispatches a strongly-typed IOCTL command to the KMDF driver.
    ///
    /// # Arguments
    ///
    /// * `command` - Concrete reference to an `IoctlMessage` payload.
    ///
    /// # Returns
    ///
    /// The decoded `C::Response` structure populated by the driver.
    ///
    /// # Errors
    ///
    /// Returns [`DriverError::WindowsApi`] if `DeviceIoControl` fails, or [`DriverError::IoctlResponseTruncated`].
    pub fn send<C: IoctlMessage>(&self, command: &C) -> Result<C::Response, DriverError> {
        // Prepare an uninitialized memory block for the exact type of the expected response.
        let mut response = std::mem::MaybeUninit::<C::Response>::uninit();
        let mut bytes_returned = 0;

        let input_ptr = command as *const _ as *const c_void;
        let input_size = size_of::<C>() as u32;

        let output_ptr = response.as_mut_ptr() as *mut c_void;
        let output_size = size_of::<C::Response>() as u32;

        log::debug!(target: "kmdf", "Dispatching IOCTL: {:#X}", C::CODE);

        // SAFETY:
        // - `self.0` is guaranteed to be a valid handle by the `connect` constructor.
        // - Buffer sizes are strictly derived from the concrete Rust types at compile time.
        // - Pointers are safely cast to c_void as required by the Win32 API.
        let success = unsafe {
            DeviceIoControl(
                self.0,
                C::CODE,
                input_ptr,
                input_size,
                output_ptr,
                output_size,
                &mut bytes_returned,
                ptr::null_mut(),
            )
        };

        if success == 0 {
            let err = unsafe { GetLastError() };
            return Err(DriverError::from_win32_code(err));
        }

        let expected_size = size_of::<C::Response>();
        // Verify the driver returned the full expected response buffer before assuming initialization.
        // Reading from uninitialized memory when bytes_returned is smaller than expected_size causes undefined behavior.
        if expected_size > 0 && (bytes_returned as usize) < expected_size {
            return Err(DriverError::IoctlResponseTruncated {
                code: C::CODE,
                expected: expected_size,
                received: bytes_returned as usize,
            });
        }

        // SAFETY: The kernel driver succeeded and populated at least expected_size bytes.
        let initialized_response = unsafe { response.assume_init() };

        Ok(initialized_response)
    }
}
