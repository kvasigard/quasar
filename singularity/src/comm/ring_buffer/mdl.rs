//! RAII wrapper for Memory Descriptor Lists (MDLs) projected into user space.

use core::ffi::c_void;
use core::ptr::{self, NonNull};

use wdk_sys::{
    _MEMORY_CACHING_TYPE::MmCached, _MODE::UserMode, KPROCESSOR_MODE, MDL,
    ntddk::{
        IoAllocateMdl, IoFreeMdl, MmBuildMdlForNonPagedPool, MmMapLockedPagesSpecifyCache,
        MmUnmapLockedPages,
    },
};

use super::error::RingBufferError;

/// RAII wrapper for an individual Memory Descriptor List (MDL) mapped into user space.
///
/// Encapsulates the user-mode virtual address and its underlying MDL. When dropped, it
/// automatically invokes [`MmUnmapLockedPages`] and [`IoFreeMdl`] to release operating
/// system page tables and descriptor structures cleanly without leaks.
pub(crate) struct MdlSection {
    user_addr: NonNull<c_void>,
    mdl: NonNull<MDL>,
}

unsafe impl Send for MdlSection {}

impl MdlSection {
    /// Allocates an MDL for non-paged kernel pool memory, builds it, and maps it into
    /// the virtual address space of the calling user-mode process.
    ///
    /// Executes at `PASSIVE_LEVEL` in the context of the calling process to modify page tables
    /// safely without triggering kernel bug checks.
    ///
    /// # Safety
    /// Caller must ensure `memory_addr` points to valid NonPaged kernel pool memory of at least `size`
    /// bytes and that the call executes in the virtual address context of the target process.
    ///
    /// # Arguments
    ///
    /// * `memory_addr` - Base non-paged kernel pool address to project.
    /// * `size` - Size in bytes of the memory region to describe.
    /// * `priority` - Page priority and protection attributes (e.g. `MdlMappingNoExecute`).
    ///
    /// # Return values
    ///
    /// * `Ok(Self)` - MDL allocated, locked, and mapped into user space.
    /// * `Err(RingBufferError::MdlAllocationFailed)` - `IoAllocateMdl` failed.
    /// * `Err(RingBufferError::MdlMappingFailed)` - `MmMapLockedPagesSpecifyCache` returned null.
    pub(crate) unsafe fn new(
        memory_addr: NonNull<c_void>,
        size: u32,
        priority: u32,
    ) -> Result<Self, RingBufferError> {
        let mdl_raw = unsafe { IoAllocateMdl(memory_addr.as_ptr(), size, 0, 0, ptr::null_mut()) };
        let mdl = NonNull::new(mdl_raw).ok_or(RingBufferError::MdlAllocationFailed)?;

        // Populate the MDL with the physical page frame numbers of the non-paged pool pages
        unsafe {
            MmBuildMdlForNonPagedPool(mdl.as_ptr());
        }

        // Map the physical pages into the user-mode address space with specified caching and protection
        let user_addr_raw = unsafe {
            MmMapLockedPagesSpecifyCache(
                mdl.as_ptr(),
                UserMode as KPROCESSOR_MODE,
                MmCached,
                ptr::null_mut(),
                0,
                priority,
            )
        };

        let user_addr = match NonNull::new(user_addr_raw) {
            Some(addr) => addr,
            None => {
                // If mapping fails, free the MDL to prevent a descriptor leak
                unsafe {
                    IoFreeMdl(mdl.as_ptr());
                }
                return Err(RingBufferError::MdlMappingFailed);
            }
        };

        Ok(Self { user_addr, mdl })
    }

    /// Returns the mapped virtual address within the user-mode process.
    ///
    /// Points to the base address visible to the user-mode reader thread.
    ///
    /// # Return values
    ///
    /// * `NonNull<c_void>` - Non-null user-mode virtual pointer.
    #[inline(always)]
    pub(crate) fn user_addr(&self) -> NonNull<c_void> {
        self.user_addr
    }

    /// Returns the underlying Memory Descriptor List pointer.
    ///
    /// Points to the NT kernel descriptor describing the locked physical pages.
    ///
    /// # Return values
    ///
    /// * `NonNull<MDL>` - Non-null pointer to the kernel MDL.
    #[inline(always)]
    pub(crate) fn mdl(&self) -> NonNull<MDL> {
        self.mdl
    }
}

impl Drop for MdlSection {
    /// Unmaps the locked user pages and frees the MDL.
    ///
    /// # IRQL Requirement
    /// Like mapping, `MmUnmapLockedPages` for user-space addresses must execute at
    /// `IRQL <= APC_LEVEL` (`PASSIVE_LEVEL`). Never drop an `MdlSection` while holding a spinlock.
    fn drop(&mut self) {
        unsafe {
            MmUnmapLockedPages(self.user_addr.as_ptr(), self.mdl.as_ptr());
            IoFreeMdl(self.mdl.as_ptr());
        }
    }
}
