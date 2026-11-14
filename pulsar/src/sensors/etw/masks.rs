//! System Logger `PERFINFO_GROUPMASK` (`[u32; 8]`) and kernel telemetry group flags.
//!
//! Classic V1 `EVENT_TRACE_PROPERTIES.EnableFlags` only exposes `Masks[0]`, making it impossible
//! to enable extended kernel telemetry groups such as `PERF_VIRTUAL_ALLOC` (`Masks[2]`) or
//! `PERF_OB_HANDLE` (`Masks[4]`). [`PerfGroupMask`] implements the Windows `ntwmi.h` 8-slot
//! bitmask encoding used by `EVENT_TRACE_PROPERTIES_V2` (`ETW_EXT_ENABLE_FLAGS`) and
//! `TraceSetInformation(TraceSystemTraceEnableFlagsInfo)`.

use std::ops::{BitOr, BitOrAssign};

/// Bitmask extracting the 29-bit group value within a single `PerfGroupMask` slot.
const PERF_MASK_VALUE: u32 = !0xE000_0000;

/// Bit shift extracting the 3-bit slot index (`0..=7`) from a `PERF_*` constant.
const PERF_MASK_INDEX_SHIFT: u32 = 29;

// ---------------------------------------------------------------------------
// Group 0 (`Masks[0]` — Legacy `EVENT_TRACE_FLAG_*` compatible)
// ---------------------------------------------------------------------------

/// Process creation, termination, and rundown events (`EVENT_TRACE_FLAG_PROCESS`).
pub const PERF_PROCESS: u32 = 0x0000_0001;
/// Thread creation, termination, and rundown events (`EVENT_TRACE_FLAG_THREAD`).
pub const PERF_THREAD: u32 = 0x0000_0002;
/// Executable and DLL image load/unload events (`EVENT_TRACE_FLAG_IMAGE_LOAD`).
pub const PERF_IMAGE_LOAD: u32 = 0x0000_0004;
/// Physical disk I/O completion events (`EVENT_TRACE_FLAG_DISK_IO`).
pub const PERF_DISK_IO: u32 = 0x0000_0100;
/// Disk file I/O attribution events (`EVENT_TRACE_FLAG_DISK_FILE_IO`).
pub const PERF_DISK_FILE_IO: u32 = 0x0000_0200;
/// Hard page fault events (`EVENT_TRACE_FLAG_MEMORY_HARD_FAULTS`).
pub const PERF_MEMORY_HARD_FAULTS: u32 = 0x0000_2000;
/// Virtual memory map/unmap events (`EVENT_TRACE_FLAG_VAMAP`).
pub const PERF_VAMAP: u32 = 0x0000_8000;
/// TCP/IP and UDP network send/receive events (`EVENT_TRACE_FLAG_NETWORK_TCPIP`).
pub const PERF_NETWORK_TCPIP: u32 = 0x0001_0000;
/// Windows Registry operation events (`EVENT_TRACE_FLAG_REGISTRY`).
pub const PERF_REGISTRY: u32 = 0x0002_0000;
/// ALPC (Advanced Local Procedure Call) IPC events (`EVENT_TRACE_FLAG_ALPC`).
pub const PERF_ALPC: u32 = 0x0010_0000;
/// Split I/O events (`EVENT_TRACE_FLAG_SPLIT_IO`).
pub const PERF_SPLIT_IO: u32 = 0x0020_0000;
/// Kernel WDM driver events (`EVENT_TRACE_FLAG_DRIVER`).
pub const PERF_DRIVER: u32 = 0x0080_0000;
/// Sampled profile interrupt events (`EVENT_TRACE_FLAG_PROFILE`).
pub const PERF_PROFILE: u32 = 0x0100_0000;
/// File I/O completion events (`EVENT_TRACE_FLAG_FILE_IO`).
pub const PERF_FILE_IO: u32 = 0x0200_0000;
/// File I/O initiation events (`EVENT_TRACE_FLAG_FILE_IO_INIT`).
pub const PERF_FILE_IO_INIT: u32 = 0x0400_0000;

// ---------------------------------------------------------------------------
// Extended Groups (`Masks[1..7]` — Requires `PerfGroupMask` / V2 Properties)
// ---------------------------------------------------------------------------

/// System call entry/exit transitions (`EVENT_TRACE_FLAG_SYSTEMCALL`, `Masks[1]` bit `0x40`).
pub const PERF_SYSCALL: u32 = 0x2000_0040;
/// Thread context switch events (`EVENT_TRACE_FLAG_CSWITCH`, `Masks[1]` bit `0x04`).
pub const PERF_CONTEXT_SWITCH: u32 = 0x2000_0004;
/// Ready thread dispatcher events (`EVENT_TRACE_FLAG_DISPATCHER`, `Masks[1]` bit `0x200`).
pub const PERF_DISPATCHER: u32 = 0x2000_0200;
/// Virtual memory allocation/free (`NtAllocateVirtualMemory` / `NtFreeVirtualMemory`, `Masks[2]` bit `0x4000`).
pub const PERF_VIRTUAL_ALLOC: u32 = 0x4000_4000;
/// Object Manager handle creation/duplication/closure (`Ob` handle operations, `Masks[4]` bit `0x40`).
pub const PERF_OB_HANDLE: u32 = 0x8000_0040;

/// Strongly-typed enumeration of kernel trace flags supported by the System Logger.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KernelFlag {
    /// Process creation and termination (`PERF_PROCESS`).
    Process = PERF_PROCESS,
    /// Thread creation and termination (`PERF_THREAD`).
    Thread = PERF_THREAD,
    /// Executable and DLL image mapping (`PERF_IMAGE_LOAD`).
    ImageLoad = PERF_IMAGE_LOAD,
    /// Physical disk I/O (`PERF_DISK_IO`).
    DiskIo = PERF_DISK_IO,
    /// Disk file I/O (`PERF_DISK_FILE_IO`).
    DiskFileIo = PERF_DISK_FILE_IO,
    /// Hard page faults (`PERF_MEMORY_HARD_FAULTS`).
    MemoryHardFaults = PERF_MEMORY_HARD_FAULTS,
    /// Section / view mapping (`PERF_VAMAP`).
    VaMap = PERF_VAMAP,
    /// TCP/IP network activity (`PERF_NETWORK_TCPIP`).
    NetworkTcpip = PERF_NETWORK_TCPIP,
    /// Registry operations (`PERF_REGISTRY`).
    Registry = PERF_REGISTRY,
    /// ALPC IPC activity (`PERF_ALPC`).
    Alpc = PERF_ALPC,
    /// Split I/O (`PERF_SPLIT_IO`).
    SplitIo = PERF_SPLIT_IO,
    /// Driver I/O requests (`PERF_DRIVER`).
    Driver = PERF_DRIVER,
    /// Sampled CPU profiling (`PERF_PROFILE`).
    Profile = PERF_PROFILE,
    /// File I/O completion (`PERF_FILE_IO`).
    FileIo = PERF_FILE_IO,
    /// File I/O initiation (`PERF_FILE_IO_INIT`).
    FileIoInit = PERF_FILE_IO_INIT,
    /// System call entry/exit transitions (`PERF_SYSCALL`).
    SystemCall = PERF_SYSCALL,
    /// Context switches (`PERF_CONTEXT_SWITCH`).
    ContextSwitch = PERF_CONTEXT_SWITCH,
    /// Thread dispatcher (`PERF_DISPATCHER`).
    Dispatcher = PERF_DISPATCHER,
    /// Virtual memory allocation/deallocation (`PERF_VIRTUAL_ALLOC`).
    VirtualAlloc = PERF_VIRTUAL_ALLOC,
    /// Object Manager handle operations (`PERF_OB_HANDLE`).
    ObHandle = PERF_OB_HANDLE,
}

impl From<KernelFlag> for u32 {
    #[inline(always)]
    fn from(flag: KernelFlag) -> Self {
        flag as u32
    }
}

/// 256-bit (`[u32; 8]`) kernel trace group mask matching Windows `PERFINFO_GROUPMASK`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PerfGroupMask {
    /// The 8 32-bit group mask slots (`Masks[0..8]`).
    pub masks: [u32; 8],
}

impl PerfGroupMask {
    /// Creates an empty [`PerfGroupMask`] with all 8 slots set to `0`.
    #[inline]
    pub const fn empty() -> Self {
        Self { masks: [0; 8] }
    }

    /// Creates a [`PerfGroupMask`] containing a single raw `PERF_*` flag.
    #[inline]
    pub const fn from_raw_flag(flag: u32) -> Self {
        let mut mask = Self::empty();
        let slot = (flag >> PERF_MASK_INDEX_SHIFT) as usize;
        mask.masks[slot] |= flag & PERF_MASK_VALUE;
        mask
    }

    /// Creates a [`PerfGroupMask`] from a typed [`KernelFlag`].
    #[inline]
    pub const fn from_flag(flag: KernelFlag) -> Self {
        Self::from_raw_flag(flag as u32)
    }

    /// Enables a raw `PERF_*` constant in the appropriate `masks[0..8]` slot.
    #[inline]
    pub fn insert_raw(&mut self, flag: u32) -> &mut Self {
        let slot = (flag >> PERF_MASK_INDEX_SHIFT) as usize;
        self.masks[slot] |= flag & PERF_MASK_VALUE;
        self
    }

    /// Enables a typed [`KernelFlag`] in the appropriate `masks[0..8]` slot.
    #[inline]
    pub fn insert(&mut self, flag: KernelFlag) -> &mut Self {
        self.insert_raw(flag as u32)
    }

    /// Removes a typed [`KernelFlag`] from the mask.
    #[inline]
    pub fn remove(&mut self, flag: KernelFlag) -> &mut Self {
        let raw = flag as u32;
        let slot = (raw >> PERF_MASK_INDEX_SHIFT) as usize;
        self.masks[slot] &= !(raw & PERF_MASK_VALUE);
        self
    }

    /// Returns `true` if the specified raw `PERF_*` flag is enabled in this mask.
    #[inline]
    pub const fn contains_raw(&self, flag: u32) -> bool {
        let slot = (flag >> PERF_MASK_INDEX_SHIFT) as usize;
        let bits = flag & PERF_MASK_VALUE;
        (self.masks[slot] & bits) == bits
    }

    /// Returns `true` if the specified [`KernelFlag`] is enabled in this mask.
    #[inline]
    pub const fn contains(&self, flag: KernelFlag) -> bool {
        self.contains_raw(flag as u32)
    }

    /// Returns `true` if all 8 mask slots are zero.
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.masks[0] == 0
            && self.masks[1] == 0
            && self.masks[2] == 0
            && self.masks[3] == 0
            && self.masks[4] == 0
            && self.masks[5] == 0
            && self.masks[6] == 0
            && self.masks[7] == 0
    }

    /// Returns `true` if any extended slot (`masks[1..8]`) has bits set.
    #[inline]
    pub const fn has_extended_flags(&self) -> bool {
        self.masks[1] != 0
            || self.masks[2] != 0
            || self.masks[3] != 0
            || self.masks[4] != 0
            || self.masks[5] != 0
            || self.masks[6] != 0
            || self.masks[7] != 0
    }

    /// Computes the legacy 32-bit `EVENT_TRACE_PROPERTIES.EnableFlags` value (`masks[0]`, plus
    /// `EVENT_TRACE_FLAG_SYSTEMCALL = 0x80` if `PERF_SYSCALL` is set).
    #[inline]
    pub const fn legacy_enable_flags(&self) -> u32 {
        let mut flags = self.masks[0];
        if self.contains_raw(PERF_SYSCALL) {
            flags |= 0x0000_0080; // Legacy EVENT_TRACE_FLAG_SYSTEMCALL
        }
        if self.contains_raw(PERF_VIRTUAL_ALLOC) {
            flags |= 0x0000_4000; // Legacy EVENT_TRACE_FLAG_VIRTUAL_ALLOC
        }
        flags
    }
}

impl BitOr for PerfGroupMask {
    type Output = Self;

    #[inline]
    fn bitor(mut self, rhs: Self) -> Self::Output {
        self |= rhs;
        self
    }
}

impl BitOrAssign for PerfGroupMask {
    #[inline]
    fn bitor_assign(&mut self, rhs: Self) {
        for i in 0..8 {
            self.masks[i] |= rhs.masks[i];
        }
    }
}

impl BitOr<KernelFlag> for PerfGroupMask {
    type Output = Self;

    #[inline]
    fn bitor(mut self, rhs: KernelFlag) -> Self::Output {
        self.insert(rhs);
        self
    }
}

impl BitOrAssign<KernelFlag> for PerfGroupMask {
    #[inline]
    fn bitor_assign(&mut self, rhs: KernelFlag) {
        self.insert(rhs);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_perf_group_mask_slot_routing() {
        let mut mask = PerfGroupMask::empty();
        assert!(mask.is_empty());

        mask.insert(KernelFlag::Process)
            .insert(KernelFlag::ImageLoad)
            .insert(KernelFlag::SystemCall)
            .insert(KernelFlag::VirtualAlloc)
            .insert(KernelFlag::ObHandle);

        assert!(!mask.is_empty());
        assert!(mask.has_extended_flags());

        // Group 0: Process (0x1) | ImageLoad (0x4)
        assert_eq!(mask.masks[0], PERF_PROCESS | PERF_IMAGE_LOAD);
        // Group 1: SystemCall (0x2000_0040 -> slot 1, bit 0x40)
        assert_eq!(mask.masks[1], 0x0000_0040);
        // Group 2: VirtualAlloc (0x4000_4000 -> slot 2, bit 0x4000)
        assert_eq!(mask.masks[2], 0x0000_4000);
        // Group 4: ObHandle (0x8000_0040 -> slot 4, bit 0x40)
        assert_eq!(mask.masks[4], 0x0000_0040);

        assert!(mask.contains(KernelFlag::Process));
        assert!(mask.contains(KernelFlag::SystemCall));
        assert!(mask.contains(KernelFlag::VirtualAlloc));
        assert!(mask.contains(KernelFlag::ObHandle));
        assert!(!mask.contains(KernelFlag::Thread));
    }
}
