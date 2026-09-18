//! IOCTL communication and dispatch layer.
//!
//! Provides the entry point for user-mode requests, decodes payloads, and routes
//! commands to the appropriate domain handlers.

pub mod dispatch;
pub mod handlers;

pub use dispatch::singularity_device_control;

use wdk_sys::{NTSTATUS, STATUS_INVALID_DEVICE_REQUEST};

/// Errors originating from the IOCTL dispatch layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoctlError {
    /// The incoming IOCTL control code was not recognized.
    InvalidDeviceRequest(u32),

    /// WDF failed to retrieve the input buffer.
    BufferRetrievalFailed(NTSTATUS),
}

impl IoctlError {
    /// Maps the IOCTL error to its corresponding Windows NTSTATUS code.
    ///
    /// Preserves the original WDF error status for buffer retrieval failures
    /// (e.g. `STATUS_BUFFER_TOO_SMALL`) rather than masking it.
    pub const fn to_ntstatus(&self) -> NTSTATUS {
        match self {
            Self::InvalidDeviceRequest(_) => STATUS_INVALID_DEVICE_REQUEST,
            Self::BufferRetrievalFailed(status) => *status,
        }
    }
}

impl core::fmt::Display for IoctlError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidDeviceRequest(code) => {
                write!(
                    f,
                    "Invalid device request: unrecognized IOCTL control code ({code:#010X})"
                )
            }
            Self::BufferRetrievalFailed(status) => {
                write!(f, "Failed to retrieve IOCTL input buffer ({status:#010X})")
            }
        }
    }
}

impl core::error::Error for IoctlError {}
