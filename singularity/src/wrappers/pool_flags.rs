//! Type-safe abstractions and bitfield definitions for Windows Kernel Pool allocations.
//!
//! Wraps `POOL_FLAGS` used by `ExAllocatePool2` and `POOL_EXTENDED_PARAMETER` used by
//! `ExAllocatePool3` into idiomatic, zero-cost Rust abstractions with full bitwise operations.

use core::ops::{BitOr, BitOrAssign};
use wdk_sys::ULONG64;

/// Bitmask flags passed to `ExAllocatePool2` indicating the type of pool memory,
/// required attributes (low 32 bits), and optional attributes (high 32 bits).
///
/// Multiple flags can be combined using the bitwise OR (`|`) operator.
#[repr(u64)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PoolFlag {
    /// No flags specified.
    None = 0x0,

    // --- Required Parameters (Low 32-bits) ---
    // If the allocator does not recognize or cannot satisfy these flags, allocation fails.
    /// Passed by highest-level drivers that allocate memory to satisfy a request in the
    /// context of the originating process. Charges quota against the calling process.
    /// Lower-level drivers need not specify this flag.
    UseQuota = 0x0000_0000_0000_0001,

    /// Leaves the allocated memory uninitialized without zeroing it.
    ///
    /// The contents are indeterminant. Drivers must be extremely cautious never to leak
    /// uninitialized memory to untrusted destinations (user-mode buffers, network, etc.).
    /// 
    Uninitialized = 0x0000_0000_0000_0002,

    /// Allocates from the session-specific pool. Reserved for internal operating system use.
    Session = 0x0000_0000_0000_0004,

    /// Requests that the allocated pool memory be aligned to CPU cache lines.
    ///
    /// Treated as best-effort by the kernel allocator; do not rely on this if cache
    /// alignment is strictly required for hardware correctness.
    CacheAligned = 0x0000_0000_0000_0008,

    /// Reserved for internal operating system use.
    Reserved1 = 0x0000_0000_0000_0010,

    /// Instructs the pool allocator to raise an exception instead of returning `NULL`
    /// if the allocation request cannot be satisfied.
    RaiseOnFailure = 0x0000_0000_0000_0020,

    /// Allocates memory from the Non-Paged pool (NX / non-executable).
    ///
    /// Guaranteed to remain resident in physical RAM at all times, making it safe
    /// to access from any IRQL level (`PASSIVE_LEVEL` through `HIGH_LEVEL`).
    NonPaged = 0x0000_0000_0000_0040,

    /// Allocates memory from the Non-Paged pool with executable permissions.
    ///
    /// **Warning:** Deprecated for security. Use only if dynamic kernel code execution is strictly required.
    NonPagedExecute = 0x0000_0000_0000_0080,

    /// Allocates memory from the Paged pool.
    ///
    /// Can be paged out to disk by the Windows Memory Manager. Must only be accessed at `IRQL < DISPATCH_LEVEL`.
    /// Executable on legacy x86 architectures; non-executable on modern 64-bit platforms.
    Paged = 0x0000_0000_0000_0100,

    /// Reserved for internal operating system use.
    Reserved2 = 0x0000_0000_0000_0200,

    /// Reserved for internal operating system use.
    Reserved3 = 0x0000_0000_0000_0400,

    /// Upper boundary marker for required parameter flags (`0x0000_0000_8000_0000`).
    RequiredEnd = 0x0000_0000_8000_0000,

    // --- Optional Parameters (High 32-bits) ---
    // Satisfied opportunistically. If the allocator cannot satisfy them, allocation still proceeds.
    /// Requests memory from the Special Pool, used for kernel debugging and diagnosing
    /// buffer overruns or use-after-free conditions. Falls back to regular pool if unavailable.
    SpecialPool = 0x0000_0001_0000_0000,

    /// Upper boundary marker for optional parameter flags (`0x8000_0000_0000_0000`).
    OptionalEnd = 0x8000_0000_0000_0000,
}

impl PoolFlag {
    /// Alias to `PoolFlag::UseQuota`, marking the start of required parameter flags.
    #[allow(non_upper_case_globals)]
    pub const RequiredStart: Self = Self::UseQuota;

    /// Alias to `PoolFlag::SpecialPool`, marking the start of optional parameter flags.
    #[allow(non_upper_case_globals)]
    pub const OptionalStart: Self = Self::SpecialPool;

    /// Explicit conversion helper to `wdk_sys::ULONG64` (`u64`).
    #[inline]
    pub const fn to_ulong64(self) -> ULONG64 {
        self as ULONG64
    }
}

// Convert an individual variant directly to wdk_sys::ULONG64
impl From<PoolFlag> for ULONG64 {
    #[inline]
    fn from(flag: PoolFlag) -> Self {
        flag as ULONG64
    }
}

// Allow combining PoolFlag | PoolFlag -> wdk_sys::ULONG64
impl BitOr for PoolFlag {
    type Output = ULONG64;

    #[inline]
    fn bitor(self, rhs: Self) -> Self::Output {
        (self as ULONG64) | (rhs as ULONG64)
    }
}

// Allow chaining: (PoolFlag | PoolFlag) | PoolFlag
impl BitOr<PoolFlag> for ULONG64 {
    type Output = ULONG64;

    #[inline]
    fn bitor(self, rhs: PoolFlag) -> Self::Output {
        self | (rhs as ULONG64)
    }
}

impl BitOrAssign<PoolFlag> for ULONG64 {
    #[inline]
    fn bitor_assign(&mut self, rhs: PoolFlag) {
        *self |= rhs as ULONG64;
    }
}
