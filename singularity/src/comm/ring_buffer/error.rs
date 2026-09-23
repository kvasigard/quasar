//! Domain-specific errors for shared memory ring buffer registration and management.

use wdk_sys::{
    NTSTATUS, STATUS_ALREADY_INITIALIZED, STATUS_INSUFFICIENT_RESOURCES, STATUS_INVALID_PARAMETER,
    STATUS_UNSUCCESSFUL,
};

/// Errors that can occur during shared memory ring buffer creation and lifecycle management.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RingBufferError {
    /// Ring buffer is already initialized and active.
    AlreadyInitialized,

    /// Execution occurred at an invalid IRQL level for pool allocation.
    InvalidIrql { current: u8, max: u8 },

    /// Invalid parameter supplied for buffer creation (e.g. zero size or invalid tag).
    InvalidParameter,

    /// Pool memory allocation failed due to insufficient physical or pool memory.
    PoolAllocationFailed,
}

impl RingBufferError {
    /// Maps the ring buffer error to its corresponding Windows NTSTATUS code.
    pub const fn to_ntstatus(&self) -> NTSTATUS {
        match self {
            Self::AlreadyInitialized => STATUS_ALREADY_INITIALIZED,
            Self::InvalidIrql { .. } => STATUS_UNSUCCESSFUL,
            Self::InvalidParameter => STATUS_INVALID_PARAMETER,
            Self::PoolAllocationFailed => STATUS_INSUFFICIENT_RESOURCES,
        }
    }
}

impl core::fmt::Display for RingBufferError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::AlreadyInitialized => write!(f, "Ring buffer is already initialized"),
            Self::InvalidIrql { current, max } => {
                write!(f, "Invalid IRQL for allocation: {current} (max allowed: {max})")
            }
            Self::InvalidParameter => write!(f, "Invalid parameter supplied for ring buffer allocation"),
            Self::PoolAllocationFailed => write!(f, "ExAllocatePool2 failed due to insufficient resources"),
        }
    }
}

impl core::error::Error for RingBufferError {}
