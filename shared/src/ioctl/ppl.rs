//! Process Protection Level (PPL) IOCTL definitions and payload structures.

use crate::ctl_code;
use super::{IoctlMessage, FILE_ANY_ACCESS, METHOD_BUFFERED, SINGULARITY_DEVICE_TYPE};

/// Custom Function Code for elevation control (>= 2048 / 0x800).
pub const FUNCTION_ELEVATE: u32 = 0x801;

/// IOCTL control code instructing the driver to change process PPL level.
pub const IOCTL_CHANGE_PPL_LEVEL: u32 = ctl_code!(
    SINGULARITY_DEVICE_TYPE,
    FUNCTION_ELEVATE,
    METHOD_BUFFERED,
    FILE_ANY_ACCESS
);

/// Request payload to modify the Process Protection Level (PPL) of a target process.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
