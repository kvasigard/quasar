//! Domain-specific errors for shared memory ring buffer registration and management.

use wdk_sys::{
    NTSTATUS, STATUS_ALREADY_COMMITTED, STATUS_ALREADY_INITIALIZED, STATUS_INSUFFICIENT_RESOURCES,
    STATUS_INVALID_DEVICE_STATE, STATUS_INVALID_PARAMETER, STATUS_UNSUCCESSFUL,
};

/// Errors encountered during per-CPU ring buffer allocation, MDL projection, or event recording.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RingBufferError {
    /// NonPaged pool allocation for the per-CPU data buffers failed.
    DataMemoryAllocationFailed,
    /// NonPaged pool allocation for the per-CPU status headers failed.
    StatusMemoryAllocationFailed,
    /// Memory Descriptor List (MDL) allocation failed.
    MdlAllocationFailed,
    /// Virtual memory projection into user-mode address space failed.
    MdlMappingFailed,
    /// A user-mode process mapping is already active.
    AlreadyMapped,
    /// The ring buffer backing store has already been initialized.
    AlreadyInitialized,
    /// The target CPU core index exceeds the allocated core count.
    InvalidCpuIndex,
    /// Invalid parameter supplied for buffer creation or writing.
    InvalidParameter,
    /// Current IRQL violates subsystem constraints.
    InvalidIrql { current: u8, max: u8 },
    /// System pool memory exhaustion.
    PoolAllocationFailed,
    /// The ring buffer backing store is not initialized or device state is invalid.
    DeviceStateInvalid,
}

impl RingBufferError {
    /// Maps the ring buffer error to its corresponding Windows NTSTATUS code.
    pub const fn to_ntstatus(&self) -> NTSTATUS {
        match self {
            Self::DataMemoryAllocationFailed
            | Self::StatusMemoryAllocationFailed
            | Self::MdlAllocationFailed
            | Self::PoolAllocationFailed => STATUS_INSUFFICIENT_RESOURCES,
            Self::MdlMappingFailed | Self::InvalidCpuIndex => STATUS_UNSUCCESSFUL,
            Self::AlreadyMapped => STATUS_ALREADY_COMMITTED,
            Self::AlreadyInitialized => STATUS_ALREADY_INITIALIZED,
            Self::InvalidParameter => STATUS_INVALID_PARAMETER,
            Self::InvalidIrql { .. } => STATUS_UNSUCCESSFUL,
            Self::DeviceStateInvalid => STATUS_INVALID_DEVICE_STATE,
        }
    }
}

impl From<RingBufferError> for NTSTATUS {
    fn from(err: RingBufferError) -> Self {
        err.to_ntstatus()
    }
}

impl core::fmt::Display for RingBufferError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::DataMemoryAllocationFailed => {
                write!(f, "Failed to allocate NonPaged pool for per-CPU data buffers")
            }
            Self::StatusMemoryAllocationFailed => {
                write!(f, "Failed to allocate NonPaged pool for per-CPU status headers")
            }
            Self::MdlAllocationFailed => write!(f, "Failed to allocate Memory Descriptor List (MDL)"),
            Self::MdlMappingFailed => write!(f, "Failed to project MDL pages into user-mode address space"),
            Self::AlreadyMapped => write!(f, "A user-mode ring buffer mapping is already active"),
            Self::AlreadyInitialized => write!(f, "Ring buffer backing store is already initialized"),
            Self::InvalidCpuIndex => write!(f, "Target CPU core index is out of bounds"),
            Self::InvalidParameter => write!(f, "Invalid parameter supplied to ring buffer operation"),
            Self::InvalidIrql { current, max } => {
                write!(f, "Invalid IRQL {current} (maximum permitted: {max})")
            }
            Self::PoolAllocationFailed => write!(f, "System pool memory exhausted during allocation"),
            Self::DeviceStateInvalid => write!(f, "Ring buffer backing memory is not initialized"),
        }
    }
}

impl core::error::Error for RingBufferError {}
