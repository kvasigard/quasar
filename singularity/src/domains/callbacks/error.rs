//! Domain-specific errors for Object Manager callback registration and management.

use wdk_sys::{NTSTATUS, STATUS_ALREADY_INITIALIZED, STATUS_INVALID_PARAMETER, STATUS_UNSUCCESSFUL};

/// Errors that can occur during Object Manager callback registration and lifecycle management.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallbackError {
    /// The callback definition list was empty.
    EmptyCallbacksList,

    /// The number of registered operations exceeded the static capacity (4).
    MaxCapacityExceeded {
        max: usize,
        actual: usize,
    },

    /// A callback entry specified neither a pre-operation nor a post-operation routine.
    MissingRoutine {
        index: usize,
    },

    /// An altitude collision occurred with an existing filter (0xC01C0016).
    AltitudeCollision {
        status: NTSTATUS,
    },

    /// Access denied during registration, typically due to missing driver test signing or integrity checks (0xC0000022).
    AccessDenied {
        status: NTSTATUS,
    },

    /// Kernel pool allocation failure (0xC000009A).
    InsufficientResources {
        status: NTSTATUS,
    },

    /// The registration API returned a null handle despite reporting success.
    NullHandleReturned,

    /// Callbacks are already initialized and active.
    AlreadyInitialized,

    /// The kernel `ObRegisterCallbacks` call failed with an unexpected NTSTATUS code.
    RegistrationFailed {
        status: NTSTATUS,
    },
}

impl CallbackError {
    /// Maps the callback error to its corresponding Windows NTSTATUS code.
    pub const fn to_ntstatus(&self) -> NTSTATUS {
        match self {
            Self::EmptyCallbacksList
            | Self::MaxCapacityExceeded { .. }
            | Self::MissingRoutine { .. } => STATUS_INVALID_PARAMETER,
            Self::AltitudeCollision { status } => *status,
            Self::AccessDenied { status } => *status,
            Self::InsufficientResources { status } => *status,
            Self::NullHandleReturned => STATUS_UNSUCCESSFUL,
            Self::AlreadyInitialized => STATUS_ALREADY_INITIALIZED,
            Self::RegistrationFailed { status } => *status,
        }
    }
}

impl core::fmt::Display for CallbackError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::EmptyCallbacksList => write!(f, "Callback definition list is empty"),
            Self::MaxCapacityExceeded { max, actual } => {
                write!(f, "Callback count ({actual}) exceeds maximum capacity ({max})")
            }
            Self::MissingRoutine { index } => {
                write!(f, "Callback entry at index {index} defines neither pre- nor post-operation routine")
            }
            Self::AltitudeCollision { status } => {
                write!(f, "Altitude collision with existing filter ({status:#010X})")
            }
            Self::AccessDenied { status } => {
                write!(f, "Access denied during registration ({status:#010X}) - check driver signature")
            }
            Self::InsufficientResources { status } => {
                write!(f, "Insufficient pool resources for callbacks ({status:#010X})")
            }
            Self::NullHandleReturned => {
                write!(f, "ObRegisterCallbacks reported success but returned null handle")
            }
            Self::AlreadyInitialized => write!(f, "Callbacks are already initialized"),
            Self::RegistrationFailed { status } => {
                write!(f, "ObRegisterCallbacks failed with status ({status:#010X})")
            }
        }
    }
}

impl core::error::Error for CallbackError {}
