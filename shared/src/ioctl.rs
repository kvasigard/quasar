/// Standard WDK definitions for IOCTL routing and access
const METHOD_BUFFERED: u32 = 0;
const FILE_ANY_ACCESS: u32 = 0;

/// Custom Device Type (Must be >= 32768 (0x8000) for OEM/Custom drivers)
const SINGULARITY_DEVICE_TYPE: u32 = 0x8000;
/// Custom Function Code (Must be >= 2048 (0x800) for OEM/Custom drivers)
const FUNCTION_ELEVATE: u32 = 0x801;

/// Macro to generate a standard Windows IOCTL code.
/// Equivalent to the CTL_CODE macro in the Windows WDK (devioctl.h).
#[macro_export]
macro_rules! ctl_code {
    ($device_type:expr, $function:expr, $method:expr, $access:expr) => {
        (($device_type) << 16) | (($access) << 14) | (($function) << 2) | ($method)
    };
}

/// Instructs the driver to change the privileges of the process
/// indicated in the associated request payload.
pub const IOCTL_CHANGE_PPL_LEVEL: u32 = ctl_code!(
    SINGULARITY_DEVICE_TYPE,
    FUNCTION_ELEVATE,
    METHOD_BUFFERED,
    FILE_ANY_ACCESS
);

/// Represents a strongly-typed request to the KMDF driver.
pub trait IoctlMessage {
    /// The unique IOCTL control code.
    const CODE: u32;

    /// The type of the expected response.
    /// If the IOCTL does not return data, use `()`.
    type Response;
}

#[repr(C)]
#[derive(Debug)]
pub struct ChangeProcessPplLevel {
    pub process_id: u32,
    pub level: u8,
}

impl IoctlMessage for ChangeProcessPplLevel {
    const CODE: u32 = IOCTL_CHANGE_PPL_LEVEL;
    type Response = ();
}
