//! Strongly-typed KMDF driver and Service Control Manager error definitions.

use thiserror::Error;

/// Errors encountered during KMDF driver communication or SCM lifecycle management.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum DriverError {
    /// The driver service is not registered in the Service Control Manager.
    #[error("Driver service '{0}' is not registered in the Service Control Manager")]
    ServiceNotRegistered(String),

    /// Failed to open a handle to the KMDF driver device object.
    #[error("Failed to connect to KMDF device '{device}': Windows Error {code}: {message}")]
    DeviceConnectFailed {
        device: &'static str,
        code: u32,
        message: String,
    },

    /// IOCTL response buffer returned by the driver was smaller than the expected data structure.
    #[error("IOCTL {code:#X} response truncated: expected {expected} bytes, received {received} bytes")]
    IoctlResponseTruncated {
        code: u32,
        expected: usize,
        received: usize,
    },

    /// The driver service configuration contains a null binary path pointer.
    #[error("Driver service configuration contains a null binary path")]
    NullBinaryPath,

    /// A Win32 SCM or DeviceIoControl API call failed.
    #[error("Windows Driver/SCM Error {code}: {message}")]
    WindowsApi {
        code: u32,
        message: String,
    },
}

impl DriverError {
    /// Formats a Win32 error code into a structured [`DriverError::WindowsApi`] using `FormatMessageW`.
    #[inline]
    pub fn from_win32_code(code: u32) -> Self {
        let message = crate::error::format_win32_error_message(code);
        Self::WindowsApi { code, message }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_driver_error_formatting() {
        let err = DriverError::IoctlResponseTruncated {
            code: 0x222000,
            expected: 16,
            received: 8,
        };
        assert_eq!(
            err.to_string(),
            "IOCTL 0x222000 response truncated: expected 16 bytes, received 8 bytes"
        );

        let err_null = DriverError::NullBinaryPath;
        assert_eq!(
            err_null.to_string(),
            "Driver service configuration contains a null binary path"
        );

        let err_conn = DriverError::DeviceConnectFailed {
            device: "\\\\.\\SingularityDevice",
            code: 2,
            message: "The system cannot find the file specified.".to_string(),
        };
        assert_eq!(
            err_conn.to_string(),
            "Failed to connect to KMDF device '\\\\.\\SingularityDevice': Windows Error 2: The system cannot find the file specified."
        );
    }
}
