use std::ffi::c_void;
use std::ptr;

use crate::error::AppError;
use crate::win_last_error;
use shared::ioctl::IoctlMessage;
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows_sys::Win32::System::IO::DeviceIoControl;

pub struct Singularity(HANDLE);

impl Drop for Singularity {
    fn drop(&mut self) {
        log::trace!("Droping Singularity KMDF handle");
        if self.0 != INVALID_HANDLE_VALUE {
            // SAFETY: The handle is guaranteed valid or INVALID_HANDLE_VALUE.
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

impl Singularity {
    /// Acquires a handle to interact with the KMDF driver.
    pub fn connect() -> Result<Self, AppError> {
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
            return Err(win_last_error!());
        }

        log::debug!("Successfully acquired handle to Singularity KMDF driver.");

        Ok(Self(handle))
    }

    /// Dispatches a strongly-typed IOCTL command to the KMDF driver.
    ///
    /// This generic implementation automatically handles memory sizing, pointer casting,
    /// and output buffer initialization based on the `IoctlCommand` trait definition.
    pub fn send<C: IoctlMessage>(&self, command: &C) -> Result<C::Response, AppError> {
        // Prepare an uninitialized memory block for the exact type of the expected response.
        let mut response = std::mem::MaybeUninit::<C::Response>::uninit();
        let mut bytes_returned = 0;

        let input_ptr = command as *const _ as *const c_void;
        let input_size = size_of::<C>() as u32;

        let output_ptr = response.as_mut_ptr() as *mut c_void;
        let output_size = size_of::<C::Response>() as u32;

        log::debug!("Dispatching IOCTL: {:#X}", C::CODE);

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
            return Err(win_last_error!());
        }

        // SAFETY: If DeviceIoControl returns non-zero, the kernel driver has successfully
        // populated the output buffer. It is now safe to assume the memory is initialized.
        // For types like `()`, size_of is 0, and reading it is inherently safe.
        let initialized_response = unsafe { response.assume_init() };

        Ok(initialized_response)
    }
}
