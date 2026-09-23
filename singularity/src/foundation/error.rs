//! Root error handling and domain error aggregation for the Singularity driver.
//!
//! Each domain defines its own domain-specific error enum. `DriverError` acts as the
//! top-level aggregator, delegating NTSTATUS conversion and display formatting to the respective domain.

use wdk_sys::NTSTATUS;

pub use crate::comm::ring_buffer::RingBufferError;
pub use crate::device::DeviceError;
pub use crate::domains::anti_tampering::AntiTamperingError;
pub use crate::domains::callbacks::CallbackError;
pub use crate::ioctl::IoctlError;

/// Unified driver error enum aggregating errors from all functional domains and lifecycle phases.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriverError {
    /// WDF driver object creation failed during initialization.
    WdfDriverCreate(NTSTATUS),

    /// Control device or queue creation error.
    Device(DeviceError),

    /// Kernel Object Manager callback error.
    Callbacks(CallbackError),

    /// Anti-tampering / process protection domain error.
    AntiTampering(AntiTamperingError),

    /// IOCTL unmarshaling or dispatch error.
    Ioctl(IoctlError),

    /// Shared memory ring buffer transport error.
    RingBuffer(RingBufferError),
}

impl DriverError {
    /// Converts the aggregated driver error into its corresponding Windows NTSTATUS code.
    pub const fn to_ntstatus(&self) -> NTSTATUS {
        match self {
            Self::WdfDriverCreate(status) => *status,
            Self::Device(err) => err.to_ntstatus(),
            Self::Callbacks(err) => err.to_ntstatus(),
            Self::AntiTampering(err) => err.to_ntstatus(),
            Self::Ioctl(err) => err.to_ntstatus(),
            Self::RingBuffer(err) => err.to_ntstatus(),
        }
    }
}

impl core::fmt::Display for DriverError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::WdfDriverCreate(status) => {
                write!(f, "WDF driver object creation failed ({status:#010X})")
            }
            Self::Device(err) => write!(f, "Device error: {err}"),
            Self::Callbacks(err) => write!(f, "Callback error: {err}"),
            Self::AntiTampering(err) => write!(f, "Anti-tampering error: {err}"),
            Self::Ioctl(err) => write!(f, "IOCTL error: {err}"),
            Self::RingBuffer(err) => write!(f, "Ring buffer error: {err}"),
        }
    }
}

impl core::error::Error for DriverError {}

impl From<DeviceError> for DriverError {
    fn from(err: DeviceError) -> Self {
        Self::Device(err)
    }
}

impl From<CallbackError> for DriverError {
    fn from(err: CallbackError) -> Self {
        Self::Callbacks(err)
    }
}

impl From<AntiTamperingError> for DriverError {
    fn from(err: AntiTamperingError) -> Self {
        Self::AntiTampering(err)
    }
}

impl From<IoctlError> for DriverError {
    fn from(err: IoctlError) -> Self {
        Self::Ioctl(err)
    }
}

impl From<RingBufferError> for DriverError {
    fn from(err: RingBufferError) -> Self {
        Self::RingBuffer(err)
    }
}

impl From<DriverError> for NTSTATUS {
    fn from(err: DriverError) -> Self {
        err.to_ntstatus()
    }
}
