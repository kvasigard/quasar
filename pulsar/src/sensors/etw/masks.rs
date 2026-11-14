//! System Logger `PERFINFO_GROUPMASK` (`[u32; 8]`) and kernel telemetry group flags.
//!
//! # Windows Kernel Group Mask Internals
//!
//! Classic V1 `EVENT_TRACE_PROPERTIES.EnableFlags` is a single 32-bit integer that only exposes
//! Group 0 (`Masks[0]`) plus a handful of legacy compatibility aliases. High-value EDR kernel
//! groups—such as `PERF_SYSCALL` (`Masks[1]`), `PERF_VIRTUAL_ALLOC` (`Masks[2]`), and
//! `PERF_OB_HANDLE` (`Masks[4]`)—reside in extended slots of the 256-bit `PERFINFO_GROUPMASK`
//! (`[u32; 8]`) structure defined in the Windows WDK (`ntwmi.h`).
//!
//! Each `PERF_*` constant encodes both its target array index (`0..=7`) in its upper 3 bits
//! (`flag >> 29`) and its 29-bit flag value in its lower bits (`flag & !0xE000_0000`).
//!
//! [`PerfGroupMask`] implements this exact `#[repr(C)]` 32-byte layout so it can be:
//! 1. Embedded inside an `EVENT_TRACE_PROPERTIES_V2` extension block (`ETW_EXT_ENABLE_FLAGS`).
//! 2. Passed directly to `TraceSetInformation(..., TraceSystemTraceEnableFlagsInfo, ...)`.

use std::ops::{BitOr, BitOrAssign};

/// Bitmask extracting the lower 29-bit group value within a single `PerfGroupMask` slot.
///
/// In `ntwmi.h`, bits `29..=31` (`0xE000_0000`) encode the slot index `0..=7`, while bits
/// `0..=28` hold the actual enable mask for that slot.
const PERF_MASK_VALUE: u32 = !0xE000_0000;

/// Bit shift extracting the 3-bit slot index (`0..=7`) from a `PERF_*` constant.
const PERF_MASK_INDEX_SHIFT: u32 = 29;

// ---------------------------------------------------------------------------
// Group 0 (`Masks[0]` — Legacy `EVENT_TRACE_FLAG_*` compatible)
// ---------------------------------------------------------------------------

/// Process creation, termination, and rundown events (`EVENT_TRACE_FLAG_PROCESS`, `Masks[0]`).
pub const PERF_PROCESS: u32 = 0x0000_0001;
/// Thread creation, termination, and rundown events (`EVENT_TRACE_FLAG_THREAD`, `Masks[0]`).
pub const PERF_THREAD: u32 = 0x0000_0002;
/// Executable and DLL image load/unload events (`EVENT_TRACE_FLAG_IMAGE_LOAD`, `Masks[0]`).
pub const PERF_IMAGE_LOAD: u32 = 0x0000_0004;
/// Physical disk I/O completion events (`EVENT_TRACE_FLAG_DISK_IO`, `Masks[0]`).
pub const PERF_DISK_IO: u32 = 0x0000_0100;
/// Disk file I/O attribution events (`EVENT_TRACE_FLAG_DISK_FILE_IO`, `Masks[0]`).
pub const PERF_DISK_FILE_IO: u32 = 0x0000_0200;
/// Hard page fault events (`EVENT_TRACE_FLAG_MEMORY_HARD_FAULTS`, `Masks[0]`).
pub const PERF_MEMORY_HARD_FAULTS: u32 = 0x0000_2000;
/// Virtual memory map/unmap events (`EVENT_TRACE_FLAG_VAMAP`, `Masks[0]`).
pub const PERF_VAMAP: u32 = 0x0000_8000;
/// TCP/IP and UDP network send/receive events (`EVENT_TRACE_FLAG_NETWORK_TCPIP`, `Masks[0]`).
pub const PERF_NETWORK_TCPIP: u32 = 0x0001_0000;
/// Windows Registry operation events (`EVENT_TRACE_FLAG_REGISTRY`, `Masks[0]`).
pub const PERF_REGISTRY: u32 = 0x0002_0000;
/// ALPC (Advanced Local Procedure Call) IPC events (`EVENT_TRACE_FLAG_ALPC`, `Masks[0]`).
pub const PERF_ALPC: u32 = 0x0010_0000;
/// Split I/O events (`EVENT_TRACE_FLAG_SPLIT_IO`, `Masks[0]`).
pub const PERF_SPLIT_IO: u32 = 0x0020_0000;
/// Kernel WDM driver events (`EVENT_TRACE_FLAG_DRIVER`, `Masks[0]`).
pub const PERF_DRIVER: u32 = 0x0080_0000;
/// Sampled profile interrupt events (`EVENT_TRACE_FLAG_PROFILE`, `Masks[0]`).
pub const PERF_PROFILE: u32 = 0x0100_0000;
/// File I/O completion events (`EVENT_TRACE_FLAG_FILE_IO`, `Masks[0]`).
pub const PERF_FILE_IO: u32 = 0x0200_0000;
/// File I/O initiation events (`EVENT_TRACE_FLAG_FILE_IO_INIT`, `Masks[0]`).
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

/// Strongly-typed enumeration of kernel trace groups supported by the Windows System Logger.
///
/// Each variant's `u32` discriminant is its `ntwmi.h` `PERF_*` constant (encoding the
/// `0..=7` slot index in bits `29..=31` and the bitmask in bits `0..=28`).
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KernelFlag {
    /// Process creation, termination, and rundown (`PERF_PROCESS`, `Masks[0]`).
    Process = PERF_PROCESS,
    /// Thread creation, termination, and rundown (`PERF_THREAD`, `Masks[0]`).
    Thread = PERF_THREAD,
    /// Executable and DLL image mapping (`PERF_IMAGE_LOAD`, `Masks[0]`).
    ImageLoad = PERF_IMAGE_LOAD,
    /// Physical disk I/O (`PERF_DISK_IO`, `Masks[0]`).
    DiskIo = PERF_DISK_IO,
    /// Disk file I/O (`PERF_DISK_FILE_IO`, `Masks[0]`).
    DiskFileIo = PERF_DISK_FILE_IO,
    /// Hard page faults (`PERF_MEMORY_HARD_FAULTS`, `Masks[0]`).
    MemoryHardFaults = PERF_MEMORY_HARD_FAULTS,
    /// Section / view mapping (`PERF_VAMAP`, `Masks[0]`).
    VaMap = PERF_VAMAP,
    /// TCP/IP network activity (`PERF_NETWORK_TCPIP`, `Masks[0]`).
    NetworkTcpip = PERF_NETWORK_TCPIP,
    /// Registry operations (`PERF_REGISTRY`, `Masks[0]`).
    Registry = PERF_REGISTRY,
    /// ALPC IPC activity (`PERF_ALPC`, `Masks[0]`).
    Alpc = PERF_ALPC,
    /// Split I/O (`PERF_SPLIT_IO`, `Masks[0]`).
    SplitIo = PERF_SPLIT_IO,
    /// Driver I/O requests (`PERF_DRIVER`, `Masks[0]`).
    Driver = PERF_DRIVER,
    /// Sampled CPU profiling (`PERF_PROFILE`, `Masks[0]`).
    Profile = PERF_PROFILE,
    /// File I/O completion (`PERF_FILE_IO`, `Masks[0]`).
    FileIo = PERF_FILE_IO,
    /// File I/O initiation (`PERF_FILE_IO_INIT`, `Masks[0]`).
    FileIoInit = PERF_FILE_IO_INIT,
    /// System call entry/exit transitions (`PERF_SYSCALL`, `Masks[1]`).
    SystemCall = PERF_SYSCALL,
    /// Context switches (`PERF_CONTEXT_SWITCH`, `Masks[1]`).
    ContextSwitch = PERF_CONTEXT_SWITCH,
    /// Thread dispatcher (`PERF_DISPATCHER`, `Masks[1]`).
    Dispatcher = PERF_DISPATCHER,
    /// Virtual memory allocation/deallocation (`PERF_VIRTUAL_ALLOC`, `Masks[2]`).
    VirtualAlloc = PERF_VIRTUAL_ALLOC,
    /// Object Manager handle operations (`PERF_OB_HANDLE`, `Masks[4]`).
    ObHandle = PERF_OB_HANDLE,
}

impl From<KernelFlag> for u32 {
    #[inline(always)]
    fn from(flag: KernelFlag) -> Self {
        flag as u32
    }
}

/// 256-bit (`[u32; 8]`) kernel trace group mask matching the Windows WDK `PERFINFO_GROUPMASK` layout.
///
/// # Layout & FFI Invariants
///
/// Marked `#[repr(C)]` so a pointer to `PerfGroupMask` (`32` bytes) can be passed directly to
/// `TraceSetInformation(handle, TraceSystemTraceEnableFlagsInfo, ...)` or copied into an
/// `EVENT_TRACE_PROPERTIES_V2` extension block.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PerfGroupMask {
    /// The 8 32-bit group mask slots (`Masks[0..8]`).
    pub masks: [u32; 8],
}

impl PerfGroupMask {
    /// Creates an empty [`PerfGroupMask`] with all 8 slots initialized to `0`.
    #[inline]
    pub const fn empty() -> Self {
        Self { masks: [0; 8] }
    }

    /// Creates a [`PerfGroupMask`] containing a single raw `PERF_*` constant routed to its `0..=7` slot.
    #[inline]
    pub const fn from_raw_flag(flag: u32) -> Self {
        let mut mask = Self::empty();
        let slot = (flag >> PERF_MASK_INDEX_SHIFT) as usize;
        mask.masks[slot] |= flag & PERF_MASK_VALUE;
        mask
    }

    /// Creates a [`PerfGroupMask`] from a single typed [`KernelFlag`].
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

    /// Clears a typed [`KernelFlag`] from its `masks[0..8]` slot.
    #[inline]
    pub fn remove(&mut self, flag: KernelFlag) -> &mut Self {
        let raw = flag as u32;
        let slot = (raw >> PERF_MASK_INDEX_SHIFT) as usize;
        self.masks[slot] &= !(raw & PERF_MASK_VALUE);
        self
    }

    /// Returns `true` if all bits of the specified raw `PERF_*` constant are set in its target slot.
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

    /// Returns `true` if any extended slot (`masks[1..8]`) has at least one bit set.
    ///
    /// Used by [`TracePropertiesBuffer::new_v2`](super::TracePropertiesBuffer::new_v2) and
    /// [`KernelSession`](super::KernelSession) to determine whether a V2 `ETW_EXT_ENABLE_FLAGS`
    /// block and `TraceSystemTraceEnableFlagsInfo` call are required.
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

    /// Projects this 256-bit group mask onto the legacy 32-bit `EVENT_TRACE_PROPERTIES.EnableFlags` field.
    ///
    /// In addition to `masks[0]`, Windows defines two legacy compatibility bits in `EnableFlags`
    /// (`EVENT_TRACE_FLAG_SYSTEMCALL = 0x80` and `EVENT_TRACE_FLAG_VIRTUAL_ALLOC = 0x4000`) for
    /// sessions that fall back to the classic `"NT Kernel Logger"`.
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
