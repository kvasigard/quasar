//! IOCTL codes, message serialization traits, and payload structures.

pub mod ppl;
pub mod ring_buffer;

pub use ppl::*;
pub use ring_buffer::*;

/// Standard WDK definitions for IOCTL routing and access methods.
pub const METHOD_BUFFERED: u32 = 0;
/// Standard WDK definition for unrestricted device access.
pub const FILE_ANY_ACCESS: u32 = 0;

/// Custom Device Type for OEM/Custom drivers (>= 32768 / 0x8000).
pub const SINGULARITY_DEVICE_TYPE: u32 = 0x8000;

/// Macro generating a standard Windows IOCTL control code.
///
/// Equivalent to the `CTL_CODE` macro in the Windows WDK (`devioctl.h`).
#[macro_export]
macro_rules! ctl_code {
    ($device_type:expr, $function:expr, $method:expr, $access:expr) => {
        (($device_type) << 16) | (($access) << 14) | (($function) << 2) | ($method)
    };
}

/// Represents a strongly-typed IOCTL request message to the KMDF driver.
pub trait IoctlMessage {
    /// The unique 32-bit IOCTL control code.
    const CODE: u32;

    /// The expected response type returned in the output buffer.
    type Response;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verifies the CTL_CODE macro matches the Microsoft WDK specification ((Device << 16) | (Access << 14) | (Function << 2) | Method).
    /// Prevents invalid IOCTL calculations that would cause the I/O Manager to reject dispatch requests or misroute control packets.
    #[test]
    fn test_ctl_code_macro_calculation() {
        let code = ctl_code!(0x8000u32, 0x801u32, 0u32, 0u32);
        assert_eq!(code, 0x80002004u32);
        assert_eq!(IOCTL_CHANGE_PPL_LEVEL, 0x80002004u32);
        let ring_code = ctl_code!(0x8000u32, 0x802u32, 0u32, 0u32);
        assert_eq!(ring_code, 0x80002008u32);
        assert_eq!(IOCTL_INIT_RING_BUFFER, 0x80002008u32);
    }
}
