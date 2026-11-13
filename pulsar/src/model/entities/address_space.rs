//! Per-process Virtual Address Space representation (`_EPROCESS.VadRoot` / `_MMVAD`).
//!
//! In the Windows Kernel, the Memory Manager tracks every process's virtual address layout
//! inside a balanced AVL tree (`VadRoot`) of Virtual Address Descriptors (`_MMVAD`). Each
//! descriptor governs a contiguous virtual address range `[StartingVpn, EndingVpn]` and is
//! backed either by an image section on disk (`VadImageMap` -> `_CONTROL_AREA`) or by
//! private/section-mapped virtual memory (`NtAllocateVirtualMemory`, `NtProtectVirtualMemory`,
//! `NtMapViewOfSection`).
//!
//! [`ProcessAddressSpace`] models this hierarchy using two ordered [`BTreeMap`] tables keyed
//! by 64-bit `base_address`:
//! - `images` ([`MappedImage`]): Tracks `.exe` and `.dll` modules loaded via ETW `ImageLoad`
//!   events, linking each process-specific base address to its global [`Arc<BinaryImage>`].
//! - `regions` ([`VadRegion`]): Tracks dynamic virtual memory allocations, protection changes,
//!   and cross-process writes.
//!
//! # Why Two Separate `BTreeMap` Tables?
//!
//! 1. **$O(\log N)$ Range Queries**: Given any arbitrary instruction pointer (`rip`) or thread
//!    `start_address`, `BTreeMap::range(..=address).next_back()` locates the candidate region
//!    with the largest `base_address <= address` in logarithmic time.
//! 2. **Module Stomping Detection**: Attackers sometimes load a benign signed DLL (`ImageLoad`)
//!    and subsequently call `VirtualProtectEx` + `WriteProcessMemory` on a page *inside* that
//!    DLL to overwrite its `.text` section with shellcode. Keeping `images` and `regions` in
//!    separate maps ensures a sub-page `VadRegion` update never overwrites or splits the
//!    enclosing `MappedImage` entry—allowing detections to see both the backed DLL and the
//!    tampered memory page simultaneously.

use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::sync::Arc;

use crate::enrichment::pe::TrackedExport;
use crate::model::entities::binary::BinaryImage;
use crate::model::types::ProcessId;

// ============================================================================
// Win32 Memory Protection Constants & Helpers
// ============================================================================

/// Disables all access to the committed region of pages (`0x01`).
pub const PAGE_NOACCESS: u32 = 0x01;
/// Enables read-only access to the committed region of pages (`0x02`).
pub const PAGE_READONLY: u32 = 0x02;
/// Enables read-only or read/write access to the committed region of pages (`0x04`).
pub const PAGE_READWRITE: u32 = 0x04;
/// Enables read-only or copy-on-write access to a mapped view of a file mapping object (`0x08`).
pub const PAGE_WRITECOPY: u32 = 0x08;
/// Enables execute access to the committed region of pages (`0x10`).
pub const PAGE_EXECUTE: u32 = 0x10;
/// Enables execute or read-only access to the committed region of pages (`0x20`).
pub const PAGE_EXECUTE_READ: u32 = 0x20;
/// Enables execute, read-only, or read/write access to the committed region of pages (`0x40`).
pub const PAGE_EXECUTE_READWRITE: u32 = 0x40;
/// Enables execute, read-only, or copy-on-write access to a mapped view of a file mapping object (`0x80`).
pub const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;

/// Default byte tolerance window when matching a remote thread's `start_address` against a
/// loader export (`[export_va, export_va + 6]`).
///
/// Accounts for 2-byte hotpatch prologues (`mov edi, edi` / `nop`) or 5-byte inline hook
/// trampolines (`jmp rel32`) that attackers may skip past when invoking `CreateRemoteThread`.
pub const LOADER_EXPORT_MATCH_TOLERANCE: u64 = 6;

/// Checks whether a Win32 `PAGE_*` protection mask grants write access.
///
/// # Arguments
///
/// * `protection` - A Win32 memory protection constant (or bitwise combination including
///   modifier flags like `PAGE_GUARD`).
///
/// # Return values
///
/// Returns `true` if any of [`PAGE_READWRITE`], [`PAGE_WRITECOPY`], [`PAGE_EXECUTE_READWRITE`],
/// or [`PAGE_EXECUTE_WRITECOPY`] is set in `protection`; `false` otherwise.
#[inline]
pub const fn is_writable_protection(protection: u32) -> bool {
    const WRITE_MASK: u32 =
        PAGE_EXECUTE_READWRITE | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY;
    protection & WRITE_MASK != 0
}

/// Checks whether a Win32 `PAGE_*` protection mask grants code execution access.
///
/// # Arguments
///
/// * `protection` - A Win32 memory protection constant (or bitwise combination including
///   modifier flags like `PAGE_GUARD`).
///
/// # Return values
///
/// Returns `true` if any of [`PAGE_EXECUTE`], [`PAGE_EXECUTE_READ`], [`PAGE_EXECUTE_READWRITE`],
/// or [`PAGE_EXECUTE_WRITECOPY`] is set in `protection`; `false` otherwise.
#[inline]
pub const fn is_executable_protection(protection: u32) -> bool {
    const EXEC_MASK: u32 =
        PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    protection & EXEC_MASK != 0
}

// ============================================================================
// Mapped Image Entity (`_MMVAD` Image Map)
// ============================================================================

/// Represents a PE image (`.exe` or `.dll`) mapped into a specific process's virtual address space.
///
/// While [`BinaryImage`] holds the process-independent static metadata on disk (such as relative
/// export RVAs and Authenticode signatures), `MappedImage` records the ASLR `base_address` and
/// `image_size` where that binary is mapped inside one particular process.
///
/// All fields are private and read-only after construction so a mapped module's `base_address`
/// can never drift out of sync with its key in [`ProcessAddressSpace`].
#[derive(Debug, Clone)]
pub struct MappedImage {
    /// Virtual base address where the image is mapped in this process (`ImageBase`).
    base_address: u64,
    /// Mapped virtual size of the image in bytes (`ImageSize`).
    image_size: u64,
    /// QPC timestamp when the `ImageLoad` event was observed.
    load_timestamp: i64,
    /// Shared reference to the global backing binary on disk (`_CONTROL_AREA`).
    image: Arc<BinaryImage>,
}

impl MappedImage {
    /// Constructs a new [`MappedImage`] mapping `image` at `[base_address, base_address + image_size)`.
    ///
    /// # Arguments
    ///
    /// * `base_address` - The process-specific virtual base address (`ImageBase`) from `ImageLoad`.
    /// * `image_size` - The mapped virtual size in bytes (`ImageSize`).
    /// * `load_timestamp` - The high-resolution QPC timestamp when the load event occurred.
    /// * `image` - Shared reference to the system-wide [`BinaryImage`] catalog entry.
    ///
    /// # Return values
    ///
    /// Returns a newly initialized [`MappedImage`] instance.
    pub fn new(
        base_address: u64,
        image_size: u64,
        load_timestamp: i64,
        image: Arc<BinaryImage>,
    ) -> Self {
        MappedImage {
            base_address,
            image_size,
            load_timestamp,
            image,
        }
    }

    /// Returns the virtual base address where this image is mapped (`ImageBase`).
    #[inline]
    pub const fn base_address(&self) -> u64 {
        self.base_address
    }

    /// Returns the mapped virtual size of the image in bytes (`ImageSize`).
    #[inline]
    pub const fn image_size(&self) -> u64 {
        self.image_size
    }

    /// Returns the high-resolution QPC timestamp when the `ImageLoad` event occurred.
    #[inline]
    pub const fn load_timestamp(&self) -> i64 {
        self.load_timestamp
    }

    /// Returns a shared reference to the backing [`BinaryImage`] in the global catalog.
    #[inline]
    pub fn image(&self) -> &Arc<BinaryImage> {
        &self.image
    }

    /// Returns the exclusive upper virtual address bound (`base_address + image_size`),
    /// using saturating addition to prevent 64-bit overflow.
    ///
    /// # Return values
    ///
    /// Returns the 64-bit exclusive end address of this mapped module.
    #[inline]
    pub const fn end_address(&self) -> u64 {
        self.base_address.saturating_add(self.image_size)
    }

    /// Determines whether `address` falls within `[base_address, end_address())`.
    ///
    /// # Arguments
    ///
    /// * `address` - The 64-bit virtual address to test.
    ///
    /// # Return values
    ///
    /// Returns `true` if `address` lies within this module's mapped virtual range; `false` otherwise.
    #[inline]
    pub const fn contains(&self, address: u64) -> bool {
        address >= self.base_address && address < self.end_address()
    }

    /// Checks whether `start_address` targets any tracked loader export within this mapped image.
    ///
    /// Resolves each non-forwarded [`TrackedExport`] RVA from the underlying [`BinaryImage`]'s
    /// parsed [`PeMetadata`](crate::enrichment::pe::PeMetadata) by adding `self.base_address`,
    /// and tests whether `start_address` falls within `[export_va, export_va + tolerance]`.
    ///
    /// # Arguments
    ///
    /// * `start_address` - The virtual start address of a thread (e.g. from `CreateRemoteThread`).
    /// * `tolerance` - Maximum positive byte offset from the export's entry point still considered
    ///   a match (typically [`LOADER_EXPORT_MATCH_TOLERANCE`]).
    ///
    /// # Return values
    ///
    /// Returns `Some(TrackedExport)` if `start_address` matches a non-forwarded loader export in
    /// this module within `tolerance` bytes, or `None` if `start_address` is outside the module,
    /// PE metadata is not yet available, or no tracked export matches.
    pub fn match_loader_export(&self, start_address: u64, tolerance: u64) -> Option<TrackedExport> {
        if !self.contains(start_address) {
            return None;
        }

        // Retrieve parsed PE metadata from the backing BinaryImage (if background analysis completed)
        let pe = self.image.pe()?;
        for (tracked_export, export_type) in pe.exports() {
            // Skip forwarded exports (e.g. "KERNELBASE.LoadLibraryExW") because their RVA points
            // to an ASCII forwarder string in .rdata rather than executable machine code.
            if let Some(export_rva) = export_type.code_rva() {
                let export_va = self.base_address.saturating_add(export_rva as u64);
                if start_address >= export_va
                    && start_address <= export_va.saturating_add(tolerance)
                {
                    return Some(*tracked_export);
                }
            }
        }
        None
    }
}

// ============================================================================
// Dynamic Virtual Memory Region Entity (`_MMVAD` Private / Mapped View)
// ============================================================================

/// Origin classification of a tracked virtual memory region.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RegionOrigin {
    /// Region was allocated via `VirtualAlloc` / `VirtualAllocEx` / `NtAllocateVirtualMemory`.
    Allocated,
    /// Region was mapped via `MapViewOfFile` / `NtMapViewOfSection`.
    MappedView,
    /// Region was not observed at allocation time, but appeared during a `VirtualProtect` /
    /// `NtProtectVirtualMemory` call (e.g. modifying pre-existing memory or stomping a module).
    UntrackedProtected,
}

/// Represents a dynamic private or section-mapped virtual memory region inside a process.
///
/// Fields are private to enforce state-machine invariants:
/// - `transitioned_w_to_x` is automatically computed at construction in [`VadRegion::new`]
///   (if initially `RWX`) and monotonically latched in [`ProcessAddressSpace::upsert_region`].
/// - `origin`, `initial_protection`, and `creator_pid` are immutable once tracked in
///   [`ProcessAddressSpace`], preventing subsequent `VirtualProtectEx` events from erasing
///   initial allocation provenance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VadRegion {
    /// Starting virtual base address of the region (`BaseAddress`).
    base_address: u64,
    /// Size of the region in bytes (`RegionSize`).
    region_size: u64,
    /// How this region was first introduced into tracking.
    origin: RegionOrigin,
    /// Initial Win32 `PAGE_*` protection flags when first observed.
    initial_protection: u32,
    /// Most recent Win32 `PAGE_*` protection flags.
    current_protection: u32,
    /// `true` if this region ever transitioned from Writable to Executable (`RW -> RX` / `RWX`),
    /// or was initially allocated as `RWX` (`PAGE_EXECUTE_READWRITE` / `PAGE_EXECUTE_WRITECOPY`).
    transitioned_w_to_x: bool,
    /// `true` if a cross-process memory write (`WriteProcessMemory` / `NtWriteVirtualMemory`)
    /// has targeted this region.
    has_been_written: bool,
    /// Process ID that initially allocated or mapped this region.
    creator_pid: ProcessId,
    /// Process ID that most recently modified (protected or wrote to) this region.
    last_modifier_pid: ProcessId,
    /// QPC timestamp when the region was last created or modified.
    last_modified_qpc: i64,
}

impl VadRegion {
    /// Constructs a new [`VadRegion`] from an observed virtual memory operation.
    ///
    /// Automatically initializes `initial_protection` and `current_protection` to `protection`,
    /// sets `creator_pid` and `last_modifier_pid` to `actor_pid`, and computes the initial
    /// `transitioned_w_to_x` flag if `protection` is simultaneously writable and executable (`RWX`).
    ///
    /// # Arguments
    ///
    /// * `base_address` - Starting virtual address of the region (`BaseAddress`).
    /// * `region_size` - Size of the region in bytes (`RegionSize`).
    /// * `origin` - How the region was introduced ([`RegionOrigin`]).
    /// * `protection` - Win32 `PAGE_*` protection mask observed on the operation.
    /// * `has_been_written` - Whether a cross-process write was observed on this region.
    /// * `actor_pid` - Process ID performing the allocation, mapping, or protection change.
    /// * `timestamp_qpc` - High-resolution QPC timestamp of the event.
    ///
    /// # Return values
    ///
    /// Returns a newly initialized [`VadRegion`] with invariant flags properly set.
    pub const fn new(
        base_address: u64,
        region_size: u64,
        origin: RegionOrigin,
        protection: u32,
        has_been_written: bool,
        actor_pid: ProcessId,
        timestamp_qpc: i64,
    ) -> Self {
        let is_rwx = is_writable_protection(protection) && is_executable_protection(protection);
        VadRegion {
            base_address,
            region_size,
            origin,
            initial_protection: protection,
            current_protection: protection,
            transitioned_w_to_x: is_rwx,
            has_been_written,
            creator_pid: actor_pid,
            last_modifier_pid: actor_pid,
            last_modified_qpc: timestamp_qpc,
        }
    }

    /// Returns the starting virtual base address of the region (`BaseAddress`).
    #[inline]
    pub const fn base_address(&self) -> u64 {
        self.base_address
    }

    /// Returns the size of the region in bytes (`RegionSize`).
    #[inline]
    pub const fn region_size(&self) -> u64 {
        self.region_size
    }

    /// Returns how this region was first introduced into tracking ([`RegionOrigin`]).
    #[inline]
    pub const fn origin(&self) -> RegionOrigin {
        self.origin
    }

    /// Returns the initial Win32 `PAGE_*` protection flags when the region was first observed.
    #[inline]
    pub const fn initial_protection(&self) -> u32 {
        self.initial_protection
    }

    /// Returns the most recent Win32 `PAGE_*` protection flags on the region.
    #[inline]
    pub const fn current_protection(&self) -> u32 {
        self.current_protection
    }

    /// Returns `true` if this region ever transitioned from Writable to Executable (`W -> X`)
    /// or was initially allocated with simultaneous `RWX` permissions.
    #[inline]
    pub const fn transitioned_w_to_x(&self) -> bool {
        self.transitioned_w_to_x
    }

    /// Returns `true` if a cross-process memory write has targeted this region.
    #[inline]
    pub const fn has_been_written(&self) -> bool {
        self.has_been_written
    }

    /// Returns the [`ProcessId`] that initially allocated or mapped this region.
    #[inline]
    pub const fn creator_pid(&self) -> ProcessId {
        self.creator_pid
    }

    /// Returns the [`ProcessId`] that most recently modified (protected or wrote to) this region.
    #[inline]
    pub const fn last_modifier_pid(&self) -> ProcessId {
        self.last_modifier_pid
    }

    /// Returns the QPC timestamp when the region was last created or modified.
    #[inline]
    pub const fn last_modified_qpc(&self) -> i64 {
        self.last_modified_qpc
    }

    /// Returns the exclusive upper virtual address bound (`base_address + region_size`),
    /// using saturating addition to prevent 64-bit overflow.
    ///
    /// # Return values
    ///
    /// Returns the 64-bit exclusive end address of this memory region.
    #[inline]
    pub const fn end_address(&self) -> u64 {
        self.base_address.saturating_add(self.region_size)
    }

    /// Determines whether `address` falls within `[base_address, end_address())`.
    ///
    /// # Arguments
    ///
    /// * `address` - The 64-bit virtual address to test.
    ///
    /// # Return values
    ///
    /// Returns `true` if `address` lies within this region's virtual address bounds; `false` otherwise.
    #[inline]
    pub const fn contains(&self, address: u64) -> bool {
        address >= self.base_address && address < self.end_address()
    }

    /// Returns `true` if `current_protection` grants code execution (`PAGE_EXECUTE*`).
    ///
    /// # Return values
    ///
    /// Returns `true` if the region is currently executable; `false` otherwise.
    #[inline]
    pub const fn is_executable(&self) -> bool {
        is_executable_protection(self.current_protection)
    }

    /// Returns `true` if `current_protection` grants write access.
    ///
    /// # Return values
    ///
    /// Returns `true` if the region is currently writable; `false` otherwise.
    #[inline]
    pub const fn is_writable(&self) -> bool {
        is_writable_protection(self.current_protection)
    }
}

// ============================================================================
// Per-Process Virtual Address Space (`_EPROCESS.VadRoot`)
// ============================================================================

/// Per-process Virtual Address Space table tracking both mapped PE images and dynamic memory regions.
#[derive(Debug, Clone, Default)]
pub struct ProcessAddressSpace {
    /// Mapped PE images (`.exe` and `.dll`s) keyed by `base_address`.
    images: BTreeMap<u64, MappedImage>,
    /// Dynamic virtual memory allocations/protections keyed by `base_address`.
    regions: BTreeMap<u64, VadRegion>,
}

impl ProcessAddressSpace {
    /// Creates an empty [`ProcessAddressSpace`].
    ///
    /// # Return values
    ///
    /// Returns a new [`ProcessAddressSpace`] with empty image and region trees.
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts or replaces a [`MappedImage`] in the process's address space keyed by `module.base_address`.
    ///
    /// # Arguments
    ///
    /// * `module` - The [`MappedImage`] descriptor to register at `module.base_address`.
    pub fn insert_image(&mut self, module: MappedImage) {
        self.images.insert(module.base_address, module);
    }

    /// Removes and returns a [`MappedImage`] at `base_address` upon receiving an `ImageUnload` event.
    ///
    /// # Arguments
    ///
    /// * `base_address` - The virtual base address of the module being unloaded.
    ///
    /// # Return values
    ///
    /// Returns `Some(MappedImage)` if a module was mapped at `base_address`, or `None` if no
    /// entry existed.
    pub fn remove_image(&mut self, base_address: u64) -> Option<MappedImage> {
        self.images.remove(&base_address)
    }

    /// Finds the [`MappedImage`] whose `[base_address, end_address())` contains `address` in $O(\log N)$ time.
    ///
    /// Queries the ordered `images` [`BTreeMap`] for the entry with the largest `base_address <= address`
    /// and verifies that `address` falls below `module.end_address()`.
    ///
    /// # Arguments
    ///
    /// * `address` - The 64-bit virtual address (such as a thread `start_address` or instruction pointer)
    ///   to resolve.
    ///
    /// # Return values
    ///
    /// Returns `Some(&MappedImage)` if `address` falls inside a currently mapped PE image, or `None`
    /// if `address` is in unmapped memory or private/heap space.
    pub fn find_image_at(&self, address: u64) -> Option<&MappedImage> {
        // Locate the candidate image with the greatest base_address <= address in O(log N) time
        let (_, module) = self.images.range(..=address).next_back()?;
        module.contains(address).then_some(module)
    }

    /// Checks if `start_address` falls within `[export_va, export_va + LOADER_EXPORT_MATCH_TOLERANCE]`
    /// of any tracked loader export in the process's loaded modules.
    ///
    /// First resolves the enclosing [`MappedImage`] in $O(\log N)$ time via [`Self::find_image_at`],
    /// then checks whether `start_address` matches any tracked loader export (`LoadLibraryA/W`,
    /// `LoadLibraryExA/W`, `LdrLoadDll`) within [`LOADER_EXPORT_MATCH_TOLERANCE`] bytes.
    ///
    /// # Arguments
    ///
    /// * `start_address` - The virtual start address of a newly created thread.
    ///
    /// # Return values
    ///
    /// Returns `Some((TrackedExport, &MappedImage))` identifying both the matched loader function
    /// and the module exporting it, or `None` if `start_address` does not target a known loader export.
    pub fn match_loader_export(&self, start_address: u64) -> Option<(TrackedExport, &MappedImage)> {
        let module = self.find_image_at(start_address)?;
        let matched_export =
            module.match_loader_export(start_address, LOADER_EXPORT_MATCH_TOLERANCE)?;
        Some((matched_export, module))
    }

    /// Inserts a new [`VadRegion`] or updates an existing region at `region.base_address`.
    ///
    /// # State Merge Rules
    ///
    /// - **Existing Region (`Entry::Occupied`)**: When `VirtualProtectEx` or another virtual memory
    ///   operation modifies an already-tracked `base_address`:
    ///   - Preserves historical provenance (`origin`, `initial_protection`, and `creator_pid`).
    ///   - Updates `current_protection`, `region_size`, `last_modifier_pid`, and `last_modified_qpc`.
    ///   - Monotonically latches boolean taint indicators (`has_been_written` and `transitioned_w_to_x`)
    ///     so a multi-stage `RW -> R -> RX` or `RW -> RX` sequence permanently records the W->X transition.
    /// - **New Region (`Entry::Vacant`)**: If the region is initially allocated with simultaneous
    ///   write and execute permissions (e.g. `PAGE_EXECUTE_READWRITE`), latches
    ///   `region.transitioned_w_to_x = true` immediately upon insertion.
    ///
    /// # Arguments
    ///
    /// * `region` - The incoming [`VadRegion`] state to insert or merge at `region.base_address`.
    pub fn upsert_region(&mut self, mut region: VadRegion) {
        match self.regions.entry(region.base_address) {
            Entry::Occupied(mut entry) => {
                let existing = entry.get_mut();
                // Check if the region was ever writable (either at initial allocation or in its
                // prior protection state) before overwriting `current_protection`.
                let was_writable =
                    is_writable_protection(existing.initial_protection) || existing.is_writable();
                let now_executable = is_executable_protection(region.current_protection);

                existing.current_protection = region.current_protection;
                existing.region_size = region.region_size;
                existing.last_modifier_pid = region.last_modifier_pid;
                existing.last_modified_qpc = region.last_modified_qpc;
                existing.has_been_written |= region.has_been_written;
                existing.transitioned_w_to_x |=
                    region.transitioned_w_to_x || (was_writable && now_executable);
            }
            Entry::Vacant(entry) => {
                // Immediately flag regions allocated with RWX / WCX permissions
                region.transitioned_w_to_x |= region.is_writable() && region.is_executable();
                entry.insert(region);
            }
        }
    }

    /// Finds the [`VadRegion`] whose `[base_address, end_address())` contains `address` in $O(\log N)$ time.
    ///
    /// Queries the ordered `regions` [`BTreeMap`] for the entry with the largest `base_address <= address`
    /// and verifies that `address` falls below `region.end_address()`.
    ///
    /// # Arguments
    ///
    /// * `address` - The 64-bit virtual address to look up in the dynamic region table.
    ///
    /// # Return values
    ///
    /// Returns `Some(&VadRegion)` if `address` falls within a tracked memory region, or `None` otherwise.
    pub fn find_region_at(&self, address: u64) -> Option<&VadRegion> {
        // Locate the candidate region with the greatest base_address <= address in O(log N) time
        let (_, region) = self.regions.range(..=address).next_back()?;
        region.contains(address).then_some(region)
    }

    /// Returns an iterator over all currently mapped images in ascending `base_address` order.
    ///
    /// # Return values
    ///
    /// Returns an iterator yielding shared references to each [`MappedImage`].
    pub fn images(&self) -> impl Iterator<Item = &MappedImage> {
        self.images.values()
    }

    /// Returns an iterator over all tracked dynamic memory regions in ascending `base_address` order.
    ///
    /// # Return values
    ///
    /// Returns an iterator yielding shared references to each [`VadRegion`].
    pub fn regions(&self) -> impl Iterator<Item = &VadRegion> {
        self.regions.values()
    }
}

// ============================================================================
// Unit Test Suite
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enrichment::pe::{ExportTarget, PeArchitecture, PeMetadata};
    use crate::enrichment::signature::SeSigningLevel;
    use crate::model::entities::binary::BinaryMetadata;
    use std::collections::HashMap;

    /// Helper to create a mock `Arc<BinaryImage>` with custom tracked exports.
    fn create_mock_binary(
        path: &str,
        size_of_image: u32,
        exports: &[(TrackedExport, ExportTarget)],
    ) -> Arc<BinaryImage> {
        let img = BinaryImage::new(path);
        let mut export_map = HashMap::new();
        for (k, v) in exports {
            export_map.insert(*k, v.clone());
        }

        let meta = Arc::new(BinaryMetadata::new(
            None,
            None,
            SeSigningLevel::Windows,
            Some(PeMetadata::new(
                PeArchitecture::X64,
                true,
                size_of_image,
                0x1000,
                0,
                0,
                export_map,
            )),
        ));
        let _ = img.set_metadata(meta);
        Arc::new(img)
    }

    #[test]
    fn test_memory_protection_flags_classification() {
        // Non-writable, non-executable
        assert!(!is_writable_protection(PAGE_NOACCESS));
        assert!(!is_executable_protection(PAGE_NOACCESS));
        assert!(!is_writable_protection(PAGE_READONLY));
        assert!(!is_executable_protection(PAGE_READONLY));

        // Writable only
        assert!(is_writable_protection(PAGE_READWRITE));
        assert!(!is_executable_protection(PAGE_READWRITE));
        assert!(is_writable_protection(PAGE_WRITECOPY));
        assert!(!is_executable_protection(PAGE_WRITECOPY));

        // Executable only
        assert!(!is_writable_protection(PAGE_EXECUTE));
        assert!(is_executable_protection(PAGE_EXECUTE));
        assert!(!is_writable_protection(PAGE_EXECUTE_READ));
        assert!(is_executable_protection(PAGE_EXECUTE_READ));

        // Both Writable and Executable (RWX / WCX), even with PAGE_GUARD (0x100) set
        assert!(is_writable_protection(PAGE_EXECUTE_READWRITE | 0x100));
        assert!(is_executable_protection(PAGE_EXECUTE_READWRITE | 0x100));
        assert!(is_writable_protection(PAGE_EXECUTE_WRITECOPY));
        assert!(is_executable_protection(PAGE_EXECUTE_WRITECOPY));
    }

    #[test]
    fn test_mapped_image_bounds_and_contains() {
        let bin = create_mock_binary("C:\\Windows\\System32\\ntdll.dll", 0x2000, &[]);
        let mapped = MappedImage::new(0x7FFB_0000_0000, 0x2000, 100, bin);

        assert_eq!(mapped.end_address(), 0x7FFB_0000_2000);
        assert!(!mapped.contains(0x7FFA_FFFF_FFFF));
        assert!(mapped.contains(0x7FFB_0000_0000)); // Inclusive start
        assert!(mapped.contains(0x7FFB_0000_1FFF)); // Last byte
        assert!(!mapped.contains(0x7FFB_0000_2000)); // Exclusive end
    }

    #[test]
    fn test_mapped_image_loader_export_matching_with_tolerance() {
        let k32 = create_mock_binary(
            "C:\\Windows\\System32\\kernel32.dll",
            0xC0000,
            &[
                (TrackedExport::LoadLibraryW, ExportTarget::CodeRva(0x1F480)),
                (
                    TrackedExport::LoadLibraryExW,
                    ExportTarget::Forwarded("KERNELBASE.LoadLibraryExW".to_string()),
                ),
            ],
        );

        let base = 0x7FFB_1000_0000u64;
        let mapped = MappedImage::new(base, 0xC0000, 200, k32);
        let load_lib_va = base + 0x1F480;

        // Exact match at offset +0
        assert_eq!(
            mapped.match_loader_export(load_lib_va, LOADER_EXPORT_MATCH_TOLERANCE),
            Some(TrackedExport::LoadLibraryW)
        );

        // Within tolerance (+2 prologue skip and +6 hook trampoline edge)
        assert_eq!(
            mapped.match_loader_export(load_lib_va + 2, LOADER_EXPORT_MATCH_TOLERANCE),
            Some(TrackedExport::LoadLibraryW)
        );
        assert_eq!(
            mapped.match_loader_export(load_lib_va + 6, LOADER_EXPORT_MATCH_TOLERANCE),
            Some(TrackedExport::LoadLibraryW)
        );

        // Outside tolerance (-1 and +7) must return None
        assert_eq!(
            mapped.match_loader_export(load_lib_va - 1, LOADER_EXPORT_MATCH_TOLERANCE),
            None
        );
        assert_eq!(
            mapped.match_loader_export(load_lib_va + 7, LOADER_EXPORT_MATCH_TOLERANCE),
            None
        );
    }

    #[test]
    fn test_address_space_image_lookup_and_loader_matching() {
        let mut addr_space = ProcessAddressSpace::new();

        let k32 = create_mock_binary(
            "C:\\Windows\\System32\\kernel32.dll",
            0x50000,
            &[(TrackedExport::LoadLibraryW, ExportTarget::CodeRva(0x12000))],
        );
        let ntdll = create_mock_binary(
            "C:\\Windows\\System32\\ntdll.dll",
            0x80000,
            &[(TrackedExport::LdrLoadDll, ExportTarget::CodeRva(0x24000))],
        );

        addr_space.insert_image(MappedImage::new(0x7FFB_0000_0000, 0x50000, 100, k32));
        addr_space.insert_image(MappedImage::new(0x7FFB_1000_0000, 0x80000, 110, ntdll));

        // 1. Lookup inside kernel32
        let found_k32 = addr_space
            .find_image_at(0x7FFB_0002_5000)
            .expect("Should find kernel32");
        assert_eq!(found_k32.image().file_name(), "kernel32.dll");

        // 2. Lookup in unmapped gap between kernel32 and ntdll
        assert!(addr_space.find_image_at(0x7FFB_0005_0000).is_none());
        assert!(addr_space.find_image_at(0x7FFB_0FFF_FFFF).is_none());

        // 3. Match loader exports across address space
        let (matched_exp, matched_mod) = addr_space
            .match_loader_export(0x7FFB_1002_4004) // LdrLoadDll + 4
            .expect("Should match LdrLoadDll in ntdll.dll");
        assert_eq!(matched_exp, TrackedExport::LdrLoadDll);
        assert_eq!(matched_mod.image().file_name(), "ntdll.dll");

        // 4. Unload kernel32 and verify it is no longer found
        let removed = addr_space.remove_image(0x7FFB_0000_0000);
        assert!(removed.is_some());
        assert!(addr_space.find_image_at(0x7FFB_0002_5000).is_none());
    }

    #[test]
    fn test_vad_region_upsert_and_w_to_x_transition_tracking() {
        let mut addr_space = ProcessAddressSpace::new();
        let region_base = 0x0000_0200_5000_0000u64;

        // Step 1: Remote process (PID 666) allocates RW memory in victim (PID 1000)
        addr_space.upsert_region(VadRegion::new(
            region_base,
            0x4000,
            RegionOrigin::Allocated,
            PAGE_READWRITE,
            true,
            ProcessId(666),
            1_000,
        ));

        let r1 = addr_space
            .find_region_at(region_base + 0x1234)
            .expect("Region must be found");
        assert!(r1.is_writable());
        assert!(!r1.is_executable());
        assert!(!r1.transitioned_w_to_x());

        // Step 2: Victim or injector changes protection to PAGE_EXECUTE_READ (RX)
        addr_space.upsert_region(VadRegion::new(
            region_base,
            0x4000,
            RegionOrigin::UntrackedProtected, // Should NOT overwrite original RegionOrigin::Allocated
            PAGE_EXECUTE_READ,                // Should NOT overwrite original PAGE_READWRITE
            false,                            // Should NOT clear previous has_been_written == true!
            ProcessId(1000),                  // Should NOT overwrite original creator_pid 666!
            2_000,
        ));

        let r2 = addr_space
            .find_region_at(region_base + 0x1234)
            .expect("Updated region must be found");
        assert_eq!(r2.origin(), RegionOrigin::Allocated);
        assert_eq!(r2.initial_protection(), PAGE_READWRITE);
        assert_eq!(r2.current_protection(), PAGE_EXECUTE_READ);
        assert!(r2.is_executable());
        assert!(!r2.is_writable());
        assert!(
            r2.transitioned_w_to_x(),
            "Transition from PAGE_READWRITE to PAGE_EXECUTE_READ must latch transitioned_w_to_x = true"
        );
        assert!(
            r2.has_been_written(),
            "Historical has_been_written taint must be preserved across upserts"
        );
        assert_eq!(r2.creator_pid(), ProcessId(666));
        assert_eq!(r2.last_modifier_pid(), ProcessId(1000));

        // Step 3: Multi-stage evasion (RW -> R -> RX) must still latch transitioned_w_to_x
        // via initial_protection even though current_protection is temporarily PAGE_READONLY
        let staged_base = 0x0000_0200_6000_0000u64;
        addr_space.upsert_region(VadRegion::new(
            staged_base,
            0x1000,
            RegionOrigin::Allocated,
            PAGE_READWRITE,
            true,
            ProcessId(666),
            2_500,
        ));
        addr_space.upsert_region(VadRegion::new(
            staged_base,
            0x1000,
            RegionOrigin::UntrackedProtected,
            PAGE_READONLY,
            false,
            ProcessId(666),
            3_000,
        ));
        addr_space.upsert_region(VadRegion::new(
            staged_base,
            0x1000,
            RegionOrigin::UntrackedProtected,
            PAGE_EXECUTE_READ,
            false,
            ProcessId(1000),
            4_000,
        ));
        let r3 = addr_space
            .find_region_at(staged_base)
            .expect("Staged region must be found");
        assert!(
            r3.transitioned_w_to_x(),
            "Multi-stage RW -> R -> RX must detect W->X via initial_protection"
        );
    }

    #[test]
    fn test_module_stomping_coexistence() {
        let mut addr_space = ProcessAddressSpace::new();

        // 1. Legitimate DLL mapped at 0x7FFB_8000_0000 (size 0x20000)
        let dll = create_mock_binary("C:\\Windows\\System32\\amsi.dll", 0x20000, &[]);
        addr_space.insert_image(MappedImage::new(0x7FFB_8000_0000, 0x20000, 500, dll));

        // 2. Attacker stomps a 4KB page inside amsi.dll at 0x7FFB_8000_1000 with RWX
        addr_space.upsert_region(VadRegion::new(
            0x7FFB_8000_1000,
            0x1000,
            RegionOrigin::UntrackedProtected,
            PAGE_EXECUTE_READWRITE,
            true,
            ProcessId(4444),
            600,
        ));

        // Both the backing MappedImage AND the stomped VadRegion must be discoverable at 0x7FFB_8000_1500!
        let img = addr_space
            .find_image_at(0x7FFB_8000_1500)
            .expect("MappedImage must remain intact");
        let reg = addr_space
            .find_region_at(0x7FFB_8000_1500)
            .expect("Stomped VadRegion must also be found");

        assert_eq!(img.image().file_name(), "amsi.dll");
        assert!(
            reg.transitioned_w_to_x(),
            "Initial RWX must set transitioned_w_to_x = true"
        );
        assert_eq!(reg.origin(), RegionOrigin::UntrackedProtected);
    }
}
