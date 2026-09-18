//! Domain-specific errors for anti-tampering operations.

use wdk_sys::{
    NTSTATUS, STATUS_INVALID_PARAMETER, STATUS_NOT_FOUND, STATUS_NOT_SUPPORTED,
};

/// Domain-specific errors for anti-tampering operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AntiTamperingError {
    /// Anti-tampering features are intentionally disabled in this build.
    FeatureNotImplemented,

    /// Windows kernel version retrieval failed via `RtlGetVersion`.
    VersionDetectionFailed(NTSTATUS),

    /// The detected Windows kernel build is not supported for dynamic offset resolution.
    UnsupportedWindowsBuild(u32),

    /// Looking up the target process via `PsLookupProcessByProcessId` failed.
    ProcessLookupFailed(NTSTATUS),

    /// The provided Process ID is invalid (e.g. PID 0).
    InvalidProcessId(u32),

    /// The provided protection level byte is malformed or invalid (e.g. invalid type bits).
    InvalidProtectionLevel(u8),

    /// Process lookup succeeded but returned a null PEPROCESS pointer.
    ProcessNotFound,
}

impl AntiTamperingError {
    /// Maps the domain error to its corresponding Windows NTSTATUS code.
    pub const fn to_ntstatus(&self) -> NTSTATUS {
        match self {
            Self::FeatureNotImplemented => STATUS_NOT_SUPPORTED,
            Self::VersionDetectionFailed(status) => *status,
            Self::UnsupportedWindowsBuild(_) => STATUS_NOT_SUPPORTED,
            Self::ProcessLookupFailed(status) => *status,
            Self::InvalidProcessId(_) => STATUS_INVALID_PARAMETER,
            Self::InvalidProtectionLevel(_) => STATUS_INVALID_PARAMETER,
            Self::ProcessNotFound => STATUS_NOT_FOUND,
        }
    }
}

impl core::fmt::Display for AntiTamperingError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::FeatureNotImplemented => {
                write!(
                    f,
                    "Anti-tampering features are intentionally disabled in this build"
                )
            }
            Self::VersionDetectionFailed(status) => {
                write!(
                    f,
                    "Failed to retrieve Windows kernel version ({status:#010X})"
                )
            }
            Self::UnsupportedWindowsBuild(build) => {
                write!(f, "Unsupported Windows kernel build ({build})")
            }
            Self::ProcessLookupFailed(status) => {
                write!(
                    f,
                    "Failed to lookup target process by PID ({status:#010X})"
                )
            }
            Self::InvalidProcessId(pid) => {
                write!(f, "Invalid target process ID ({pid})")
            }
            Self::InvalidProtectionLevel(level) => {
                write!(
                    f,
                    "Invalid process protection level byte ({level:#02X})"
                )
            }
            Self::ProcessNotFound => {
                write!(f, "Target process not found (null PEPROCESS returned)")
            }
        }
    }
}

impl core::error::Error for AntiTamperingError {}
