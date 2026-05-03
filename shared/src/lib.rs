#![no_std]

/// Macro to generate a standard Windows IOCTL code.
/// Equivalent to the CTL_CODE macro in the Windows WDK (devioctl.h).
#[macro_export]
macro_rules! ctl_code {
    ($device_type:expr, $function:expr, $method:expr, $access:expr) => {
        (($device_type) << 16) | (($access) << 14) | (($function) << 2) | ($method)
    };
}

/// Mimics the Windows `DEFINE_GUID` macro by generating a 16-byte array.
///
/// This implementation stores the GUID in its little-endian memory representation,
/// allowing it to be safely cast (transmuted) to `windows_sys::core::GUID`,
/// `wdk_sys::GUID`, or `windows::core::GUID`.
///
/// # Arguments
/// * `$name` - The identifier for the constant.
/// * `$l`, `$w1`, `$w2` - The Data1 (u32), Data2 (u16), and Data3 (u16) components.
/// * `$b` - The 8-byte Data4 array elements.
///
/// # Example
/// ```rust
/// define_guid!(GUID_DEVINTERFACE_USB, 0xA5DCBF10, 0x6530, 0x11D2, 0x90, 0x1F, 0x00, 0xC0, 0x4F, 0xB9, 0x51, 0xED);
///
/// // To use with wdk_sys or windows_sys:
/// let wdk_version: &wdk_sys::GUID = unsafe { core::mem::transmute(&GUID_DEVINTERFACE_USB) };
/// ```
macro_rules! define_guid {
    ($name:ident, $l:expr, $w1:expr, $w2:expr, $($b:expr),+) => {
        pub static $name: [u8; 16] = [
            ($l as u32 & 0xFF) as u8,
            (($l as u32 >> 8) & 0xFF) as u8,
            (($l as u32 >> 16) & 0xFF) as u8,
            (($l as u32 >> 24) & 0xFF) as u8,

            ($w1 as u16 & 0xFF) as u8,
            (($w1 as u16 >> 8) & 0xFF) as u8,

            ($w2 as u16 & 0xFF) as u8,
            (($w2 as u16 >> 8) & 0xFF) as u8,

            $($b as u8),+
        ];
    };
}

// ========================================================================
// WINDOWS CONSTANTS
// ========================================================================

// Device Types
pub const FILE_DEVICE_UNKNOWN: u32 = 0x00000022;

// Methods (How memory is transferred between User and Kernel)
pub const METHOD_BUFFERED: u32 = 0; // Safest: OS copies data for you
pub const METHOD_IN_DIRECT: u32 = 1; // OS maps user buffer for read access
pub const METHOD_OUT_DIRECT: u32 = 2; // OS maps user buffer for write access
pub const METHOD_NEITHER: u32 = 3; // Most dangerous: Raw pointers

// Access Rights
pub const FILE_ANY_ACCESS: u32 = 0;
pub const FILE_READ_DATA: u32 = 1;
pub const FILE_WRITE_DATA: u32 = 2;

// ========================================================================
// SINGULARITY EDR SPECIFICS
// ========================================================================

// Microsoft requires 3rd party drivers to use a DeviceType between 0x8000 and 0xFFFF
pub const SINGULARITY_DEVICE_TYPE: u32 = 0x8000;

// Custom IOCTL functions must be in the range 0x800 to 0xFFF
pub const FUNCTION_PING: u32 = 0x800;
pub const FUNCTION_ELEVATE: u32 = 0x801;

pub const IOCTL_SINGULARITY_ELEVATE: u32 = ctl_code!(
    SINGULARITY_DEVICE_TYPE,
    FUNCTION_ELEVATE,
    METHOD_BUFFERED,
    FILE_ANY_ACCESS
);

// ========================================================================
// SHARED DATA STRUCTURES
// ========================================================================

/// #[repr(C)] is strictly required so the Rust compiler doesn't reorder
/// the fields, which would cause parsing errors between User and Kernel space.

#[repr(C)]
pub struct ProcessProtectionRequest {
    pub target_pid: u32,
}
