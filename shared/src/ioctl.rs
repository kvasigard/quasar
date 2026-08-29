//! IOCTL codes, message serialization traits, and payload structures.

/// Standard WDK definitions for IOCTL routing and access methods.
pub const METHOD_BUFFERED: u32 = 0;
/// Standard WDK definition for unrestricted device access.
pub const FILE_ANY_ACCESS: u32 = 0;

/// Custom Device Type for OEM/Custom drivers (>= 32768 / 0x8000).
pub const SINGULARITY_DEVICE_TYPE: u32 = 0x8000;
/// Custom Function Code for elevation control (>= 2048 / 0x800).
pub const FUNCTION_ELEVATE: u32 = 0x801;

/// Macro generating a standard Windows IOCTL control code.
///
/// Equivalent to the `CTL_CODE` macro in the Windows WDK (`devioctl.h`).
#[macro_export]
macro_rules! ctl_code {
    ($device_type:expr, $function:expr, $method:expr, $access:expr) => {
        (($device_type) << 16) | (($access) << 14) | (($function) << 2) | ($method)
    };
}

/// IOCTL control code instructing the driver to change process PPL level.
pub const IOCTL_CHANGE_PPL_LEVEL: u32 = ctl_code!(
    SINGULARITY_DEVICE_TYPE,
    FUNCTION_ELEVATE,
    METHOD_BUFFERED,
    FILE_ANY_ACCESS
);

/// Represents a strongly-typed IOCTL request message to the KMDF driver.
pub trait IoctlMessage {
    /// The unique 32-bit IOCTL control code.
    const CODE: u32;

    /// The expected response type returned in the output buffer.
    type Response;
}

/// Request payload to modify the Process Protection Level (PPL) of a target process.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ChangeProcessPplLevel {
    /// The target Process ID to elevate.
    pub process_id: u32,
    /// The bitmask representing the protection level (e.g. 0x31 for PPL-Antimalware).
    pub level: u8,
}

impl IoctlMessage for ChangeProcessPplLevel {
    const CODE: u32 = IOCTL_CHANGE_PPL_LEVEL;
    type Response = ();
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::{align_of, offset_of, size_of};

    /// Verifies the CTL_CODE macro matches the Microsoft WDK specification ((Device << 16) | (Access << 14) | (Function << 2) | Method).
    /// Prevents invalid IOCTL calculations that would cause the I/O Manager to reject dispatch requests or misroute control packets.
    #[test]
    fn test_ctl_code_macro_calculation() {
        let code = ctl_code!(0x8000u32, 0x801u32, 0u32, 0u32);
        assert_eq!(code, 0x80002004u32);
        assert_eq!(IOCTL_CHANGE_PPL_LEVEL, 0x80002004u32);
    }

    /// Verifies the C-ABI memory layout, size, alignment, and field offsets of the ChangeProcessPplLevel structure.
    /// Mandatory to prevent binary structure drift between user-mode and kernel-mode drivers which would cause kernel memory corruption.
    #[test]
    fn test_change_process_ppl_layout() {
        assert_eq!(size_of::<ChangeProcessPplLevel>(), 8);
        assert_eq!(align_of::<ChangeProcessPplLevel>(), 4);
        assert_eq!(offset_of!(ChangeProcessPplLevel, process_id), 0);
        assert_eq!(offset_of!(ChangeProcessPplLevel, level), 4);
    }
}


