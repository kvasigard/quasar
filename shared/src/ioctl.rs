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
    use core::mem::{align_of, size_of};

    /// Tests IOCTL control code bit calculation matching Windows WDK CTL_CODE macro.
    #[test]
    fn test_ioctl_code_calculation() {
        let expected_code = (0x8000 << 16) | (0x801 << 2);
        assert_eq!(IOCTL_CHANGE_PPL_LEVEL, expected_code);
        assert_eq!(ChangeProcessPplLevel::CODE, expected_code);
    }

    /// Verifies C-ABI layout, size, and field alignment to prevent kernel memory corruption.
    #[test]
    fn test_change_process_ppl_layout() {
        // process_id (u32, 4B) + level (u8, 1B) + 3B padding = 8 bytes total on x86_64
        assert_eq!(size_of::<ChangeProcessPplLevel>(), 8);
        assert_eq!(align_of::<ChangeProcessPplLevel>(), 4);

        let req = ChangeProcessPplLevel {
            process_id: 1337,
            level: 0x31,
        };
        assert_eq!(req.process_id, 1337);
        assert_eq!(req.level, 0x31);
    }
}
