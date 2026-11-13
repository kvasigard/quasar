//! Portable Executable (PE32 / PE32+) Header and Export Directory Parser
//!
//! Zero-dependency, bounds-checked parser for extracting static binary metadata and
//! Relative Virtual Addresses (RVAs) of security-relevant exported functions from
//! Windows executables (`.exe`) and dynamic-link libraries (`.dll`) on disk.
//!
//! # Why Parse Exports from Disk?
//!
//! Process injection techniques such as **Classic DLL Injection** (`CreateRemoteThread`
//! targeting `LoadLibraryW` or `LdrLoadDll`) begin executing a remote thread at the
//! virtual address `module_base + export_rva` inside the target process. Because ASLR
//! randomizes `module_base` per boot (and WoW64 processes map 32-bit DLLs at distinct
//! bases from 64-bit processes), computing the **static RVA** once per unique binary file
//! on disk allows [`SystemState`](crate::state::SystemState) to resolve any process's
//! live loader export address in $O(1)$ time as `loaded_module.base_address + export_rva`.
//!
//! # PE Layout Reference
//!
//! ```text
//! Offset 0x0000 +---------------------------------------------------+
//!               | IMAGE_DOS_HEADER (64 bytes)                       |
//!               |   0x00: e_magic   = 0x5A4D ("MZ")                 |
//!               |   0x3C: e_lfanew  = Offset to NT Headers (u32)    |
//!               +---------------------------------------------------+
//! Offset lfanew | IMAGE_NT_HEADERS32 / IMAGE_NT_HEADERS64           |
//!               |   +0x00: Signature = 0x00004550 ("PE\0\0")        |
//!               |   +0x04: IMAGE_FILE_HEADER (20 bytes)             |
//!               |     +0x02: NumberOfSections (u16)                 |
//!               |     +0x04: TimeDateStamp (u32)                    |
//!               |     +0x10: SizeOfOptionalHeader (u16)             |
//!               |     +0x12: Characteristics (u16)                  |
//!               |   +0x18: IMAGE_OPTIONAL_HEADER (PE32 or PE32+)    |
//!               |     +0x00: Magic (0x010B = PE32, 0x020B = PE32+)  |
//!               |     +0x10: AddressOfEntryPoint (u32)              |
//!               |     +0x38: SizeOfImage (u32)                      |
//!               |     +0x40: CheckSum (u32)                         |
//!               |     +0x5C (PE32) / +0x6C (PE32+): NumberOfRvaAndSizes (u32)
//!               |     +0x60 (PE32) / +0x70 (PE32+): DataDirectory[0] (Export)
//!               |       +0x00: VirtualAddress (u32 RVA)             |
//!               |       +0x04: Size (u32)                           |
//!               +---------------------------------------------------+
//! Section Table | IMAGE_SECTION_HEADER[NumberOfSections] (40B each) |
//! (lfanew + 24  |   +0x08: VirtualSize (u32)                        |
//!  + OptHdrSz)  |   +0x0C: VirtualAddress (u32 RVA)                 |
//!               |   +0x10: SizeOfRawData (u32)                      |
//!               |   +0x14: PointerToRawData (u32 file offset)       |
//!               |   +0x24: Characteristics (u32)                    |
//!               +---------------------------------------------------+
//! Export Dir    | IMAGE_EXPORT_DIRECTORY (40 bytes)                 |
//! (via RVA ->   |   +0x10: Base (u32)                               |
//!  File Offset) |   +0x14: NumberOfFunctions (u32)                  |
//!               |   +0x18: NumberOfNames (u32)                      |
//!               |   +0x1C: AddressOfFunctions (u32 RVA -> u32[])    |
//!               |   +0x20: AddressOfNames (u32 RVA -> u32[])        |
//!               |   +0x24: AddressOfNameOrdinals (u32 RVA -> u16[]) |
//!               +---------------------------------------------------+
//! ```
//!
//! # Documentation & Specification References
//!
//! - Microsoft PE Format Specification: <https://learn.microsoft.com/en-us/windows/win32/debug/pe-format>
//! - `IMAGE_DOS_HEADER` & `IMAGE_NT_HEADERS`: <https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_nt_headers64>
//! - Export Directory Table (`.edata`): <https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-edata-section-image-only>

use std::{
    collections::HashMap,
    fs::OpenOptions,
    io::{self, Read},
    os::windows::fs::OpenOptionsExt,
    path::Path,
};

use thiserror::Error;
use windows_sys::Win32::Storage::FileSystem::{
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
};

// ============================================================================
// PE Format Constants
// ============================================================================

/// DOS Header magic number (`"MZ"` in little-endian: `0x5A4D`).
pub const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D;

/// Size in bytes of the fixed `IMAGE_DOS_HEADER` structure (`64` bytes).
/// The `e_lfanew` field resides at byte offset `0x3C` (`60`..`64`).
pub const IMAGE_DOS_HEADER_SIZE: usize = 64;

/// Byte offset within `IMAGE_DOS_HEADER` where the 32-bit `e_lfanew` offset is stored.
pub const DOS_LFANEW_OFFSET: usize = 0x3C;

/// NT Header signature (`"PE\0\0"` in little-endian: `0x00004550`).
pub const IMAGE_NT_SIGNATURE: u32 = 0x0000_4550;

/// Size in bytes of `IMAGE_FILE_HEADER` (immediately following the 4-byte PE signature).
pub const IMAGE_FILE_HEADER_SIZE: usize = 20;

/// `IMAGE_FILE_HEADER::Characteristics` flag indicating the image is a Dynamic-Link Library (DLL).
pub const IMAGE_FILE_DLL: u16 = 0x2000;

/// Optional Header magic for 32-bit (PE32 / x86) images.
pub const IMAGE_NT_OPTIONAL_HDR32_MAGIC: u16 = 0x010B;

/// Optional Header magic for 64-bit (PE32+ / x64 / ARM64) images.
pub const IMAGE_NT_OPTIONAL_HDR64_MAGIC: u16 = 0x020B;

/// Size in bytes of a single `IMAGE_SECTION_HEADER` entry in the section table (`0x28` = `40` bytes).
pub const IMAGE_SECTION_HEADER_SIZE: usize = 40;

/// Size in bytes of `IMAGE_EXPORT_DIRECTORY` (`0x28` = `40` bytes).
pub const IMAGE_EXPORT_DIRECTORY_SIZE: usize = 40;

// ============================================================================
// Domain Models & Error Types
// ============================================================================

/// Target CPU architecture of the Portable Executable image.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PeArchitecture {
    /// 32-bit x86 (`IMAGE_NT_OPTIONAL_HDR32_MAGIC` = `0x010B`).
    X86,
    /// 64-bit x86_64 / ARM64 (`IMAGE_NT_OPTIONAL_HDR64_MAGIC` = `0x020B`).
    X64,
}

/// High-value exported symbols tracked by Pulsar for remote thread & injection detection.
///
/// Storing tracked exports keyed by this enum inside a `HashMap<TrackedExport, ExportTarget>`
/// makes expanding the set of monitored functions effortless: simply add a new enum variant
/// and map its symbol string in [`TrackedExport::from_symbol_name`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TrackedExport {
    /// `kernel32.dll` / `kernelbase.dll` ANSI DLL loader stub (`LoadLibraryA`).
    LoadLibraryA,
    /// `kernel32.dll` / `kernelbase.dll` UTF-16 DLL loader stub (`LoadLibraryW`).
    LoadLibraryW,
    /// `kernel32.dll` / `kernelbase.dll` extended ANSI DLL loader stub (`LoadLibraryExA`).
    LoadLibraryExA,
    /// `kernel32.dll` / `kernelbase.dll` extended UTF-16 DLL loader stub (`LoadLibraryExW`).
    LoadLibraryExW,
    /// `ntdll.dll` native loader entry point (`LdrLoadDll`).
    LdrLoadDll,
}

impl TrackedExport {
    /// Matches an exported ASCII symbol name from a PE Export Directory against the set of
    /// functions tracked by Pulsar.
    ///
    /// # Arguments
    ///
    /// * `name` - Exact case-sensitive ASCII symbol name read from `AddressOfNames`.
    ///
    /// # Return values
    ///
    /// * `Some(TrackedExport)` - The symbol is tracked by Pulsar.
    /// * `None` - The symbol is not currently tracked and can be skipped.
    #[inline]
    pub fn from_symbol_name(name: &str) -> Option<Self> {
        match name {
            "LoadLibraryA" => Some(Self::LoadLibraryA),
            "LoadLibraryW" => Some(Self::LoadLibraryW),
            "LoadLibraryExA" => Some(Self::LoadLibraryExA),
            "LoadLibraryExW" => Some(Self::LoadLibraryExW),
            "LdrLoadDll" => Some(Self::LdrLoadDll),
            _ => None,
        }
    }

    /// Returns the canonical ASCII symbol name for this tracked export.
    ///
    /// # Arguments
    ///
    /// * `self` - The [`TrackedExport`] variant to convert.
    ///
    /// # Return values
    ///
    /// * `&'static str` - The exact null-free ASCII export symbol name as it appears in the PE Export Directory.
    #[inline]
    pub const fn symbol_name(self) -> &'static str {
        match self {
            Self::LoadLibraryA => "LoadLibraryA",
            Self::LoadLibraryW => "LoadLibraryW",
            Self::LoadLibraryExA => "LoadLibraryExA",
            Self::LoadLibraryExW => "LoadLibraryExW",
            Self::LdrLoadDll => "LdrLoadDll",
        }
    }
}

/// Resolution target of an entry in the PE Export Directory (`AddressOfFunctions`).
///
/// According to the Microsoft PE specification, an entry in the Export Address Table (EAT)
/// is either a **Code/Data RVA** (if the RVA falls *outside* the Export Directory's own
/// `[VirtualAddress, VirtualAddress + Size)` bounds) or a **Forwarder RVA** (if it falls
/// *inside* the Export Directory bounds, pointing to an ASCII string like `"NTDLL.RtlAllocateHeap"`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExportTarget {
    /// Direct Relative Virtual Address (RVA) of the function's executable entry point within this module.
    CodeRva(u32),
    /// Forwarded export specification string (e.g. `"KERNELBASE.LoadLibraryW"` or `"NTDLL.RtlAllocateHeap"`).
    Forwarded(String),
}

impl ExportTarget {
    /// Returns the executable RVA if this export is a direct code export (`CodeRva`),
    /// or `None` if it is a forwarder string.
    ///
    /// # Arguments
    ///
    /// * `&self` - The [`ExportTarget`] entry to inspect.
    ///
    /// # Return values
    ///
    /// * `Some(u32)` - The Relative Virtual Address of the exported function within the module.
    /// * `None` - The export is a forwarder string pointing to another module.
    #[inline]
    pub const fn code_rva(&self) -> Option<u32> {
        match *self {
            Self::CodeRva(rva) => Some(rva),
            Self::Forwarded(_) => None,
        }
    }

    /// Returns the forwarder target string if this export is a forwarded symbol.
    ///
    /// # Arguments
    ///
    /// * `&self` - The [`ExportTarget`] entry to inspect.
    ///
    /// # Return values
    ///
    /// * `Some(&str)` - The `<Module>.<Symbol>` forwarder specification string.
    /// * `None` - The export is a direct code RVA within this binary.
    #[inline]
    pub fn forwarded_to(&self) -> Option<&str> {
        match self {
            Self::CodeRva(_) => None,
            Self::Forwarded(target) => Some(target.as_str()),
        }
    }

    /// Returns `true` if this export is a forwarder string rather than code in this binary.
    ///
    /// # Arguments
    ///
    /// * `&self` - The [`ExportTarget`] entry to inspect.
    ///
    /// # Return values
    ///
    /// * `true` - This export redirects to another DLL via an ASCII forwarder string.
    /// * `false` - This export points directly to code/data within the current image.
    #[inline]
    pub const fn is_forwarded(&self) -> bool {
        matches!(self, Self::Forwarded(_))
    }
}

/// Parsed fields from the `IMAGE_NT_HEADERS` (`IMAGE_FILE_HEADER` + `IMAGE_OPTIONAL_HEADER`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NtHeaderInfo {
    /// Target architecture (`X86` for `0x010B`, `X64` for `0x020B`).
    pub architecture: PeArchitecture,
    /// `true` if `IMAGE_FILE_HEADER::Characteristics` has `IMAGE_FILE_DLL` (`0x2000`) set.
    pub is_dll: bool,
    /// Number of sections reported in `IMAGE_FILE_HEADER::NumberOfSections`.
    pub num_sections: u16,
    /// Total virtual size of the loaded image in bytes (`SizeOfImage`).
    pub size_of_image: u32,
    /// RVA of the module entry point (`AddressOfEntryPoint`).
    pub entry_point_rva: u32,
    /// PE header checksum (`CheckSum`).
    pub checksum: u32,
    /// Linker compilation timestamp (`TimeDateStamp`).
    pub time_date_stamp: u32,
    /// RVA of the Export Directory (`DataDirectory[0].VirtualAddress`), or `0` if none.
    pub export_dir_rva: u32,
    /// Size in bytes of the Export Directory (`DataDirectory[0].Size`), or `0` if none.
    pub export_dir_size: u32,
    /// Raw file byte offset where the first `IMAGE_SECTION_HEADER` begins
    /// (`lfanew + 4 + 20 + SizeOfOptionalHeader`).
    pub section_table_offset: usize,
}

/// Parsed metadata for a single section from `IMAGE_SECTION_HEADER`.
///
/// Used to translate Relative Virtual Addresses (RVAs) into raw file offsets on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SectionInfo {
    /// Virtual size of the section when mapped in memory (`Misc.VirtualSize`).
    pub virtual_size: u32,
    /// Starting Relative Virtual Address (RVA) of the section (`VirtualAddress`).
    pub virtual_address: u32,
    /// Size of the initialized data on disk (`SizeOfRawData`).
    pub raw_data_size: u32,
    /// File byte offset to the section's raw data on disk (`PointerToRawData`).
    pub raw_data_offset: u32,
    /// Section characteristics flags (`Characteristics`).
    pub characteristics: u32,
}

/// Static PE metadata and tracked export table extracted from a binary file on disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeMetadata {
    /// Target CPU architecture (`X86` or `X64`).
    architecture: PeArchitecture,
    /// Whether the binary is a DLL (`true`) or an executable/driver (`false`).
    is_dll: bool,
    /// Virtual memory footprint of the image when mapped (`SizeOfImage`).
    size_of_image: u32,
    /// Entry point RVA (`AddressOfEntryPoint`).
    entry_point_rva: u32,
    /// PE CheckSum field from the Optional Header.
    checksum: u32,
    /// Compilation timestamp from `IMAGE_FILE_HEADER::TimeDateStamp`.
    time_date_stamp: u32,
    /// Map of tracked exports found in this binary's Export Directory.
    exports: HashMap<TrackedExport, ExportTarget>,
}

impl PeMetadata {
    /// Constructs a new [`PeMetadata`] instance from parsed header and export fields.
    ///
    /// # Arguments
    ///
    /// * `architecture` - Target CPU architecture (`X86` or `X64`).
    /// * `is_dll` - `true` if `IMAGE_FILE_DLL` is set in `Characteristics`.
    /// * `size_of_image` - Total virtual size of the loaded image in bytes (`SizeOfImage`).
    /// * `entry_point_rva` - RVA of the module entry point (`AddressOfEntryPoint`).
    /// * `checksum` - PE Optional Header `CheckSum`.
    /// * `time_date_stamp` - Linker compilation timestamp (`TimeDateStamp`).
    /// * `exports` - Map of tracked exports extracted from the Export Directory.
    ///
    /// # Return values
    ///
    /// Returns a newly initialized [`PeMetadata`] instance.
    pub fn new(
        architecture: PeArchitecture,
        is_dll: bool,
        size_of_image: u32,
        entry_point_rva: u32,
        checksum: u32,
        time_date_stamp: u32,
        exports: HashMap<TrackedExport, ExportTarget>,
    ) -> Self {
        Self {
            architecture,
            is_dll,
            size_of_image,
            entry_point_rva,
            checksum,
            time_date_stamp,
            exports,
        }
    }

    /// Returns the target CPU architecture ([`PeArchitecture::X86`] or [`PeArchitecture::X64`]).
    #[inline]
    pub const fn architecture(&self) -> PeArchitecture {
        self.architecture
    }

    /// Returns `true` if the binary is a Dynamic-Link Library (`IMAGE_FILE_DLL`).
    #[inline]
    pub const fn is_dll(&self) -> bool {
        self.is_dll
    }

    /// Returns the virtual memory footprint of the image when mapped (`SizeOfImage`).
    #[inline]
    pub const fn size_of_image(&self) -> u32 {
        self.size_of_image
    }

    /// Returns the Relative Virtual Address of the module entry point (`AddressOfEntryPoint`).
    #[inline]
    pub const fn entry_point_rva(&self) -> u32 {
        self.entry_point_rva
    }

    /// Returns the PE Optional Header `CheckSum`.
    #[inline]
    pub const fn checksum(&self) -> u32 {
        self.checksum
    }

    /// Returns the linker compilation timestamp (`TimeDateStamp`).
    #[inline]
    pub const fn time_date_stamp(&self) -> u32 {
        self.time_date_stamp
    }

    /// Returns an iterator over all tracked exports (`(TrackedExport, &ExportTarget)`) in this binary.
    #[inline]
    pub fn exports(&self) -> impl Iterator<Item = (&TrackedExport, &ExportTarget)> {
        self.exports.iter()
    }

    /// Looks up the [`ExportTarget`] (either `CodeRva` or `Forwarded`) for a tracked symbol.
    ///
    /// # Arguments
    ///
    /// * `&self` - The parsed [`PeMetadata`] instance.
    /// * `export` - The [`TrackedExport`] symbol to query.
    ///
    /// # Return values
    ///
    /// * `Some(&ExportTarget)` - The export exists in this binary's Export Directory.
    /// * `None` - The binary does not export the requested symbol.
    #[inline]
    pub fn get_export(&self, export: TrackedExport) -> Option<&ExportTarget> {
        self.exports.get(&export)
    }

    /// Convenience helper returning the direct executable RVA (`u32`) for `export` if present
    /// and not forwarded.
    ///
    /// # Arguments
    ///
    /// * `&self` - The parsed [`PeMetadata`] instance.
    /// * `export` - The [`TrackedExport`] symbol to query.
    ///
    /// # Return values
    ///
    /// * `Some(u32)` - The direct code RVA of the exported symbol.
    /// * `None` - The symbol is either not exported by this binary or is a forwarder string.
    #[inline]
    pub fn export_rva(&self, export: TrackedExport) -> Option<u32> {
        self.exports.get(&export).and_then(ExportTarget::code_rva)
    }
}

/// Errors encountered while parsing a Portable Executable image.
#[derive(Debug, Error)]
pub enum PeParseError {
    /// Underlying filesystem I/O failure when opening or reading the binary.
    #[error("I/O error while reading PE file: {0}")]
    Io(#[from] io::Error),

    /// Buffer ended prematurely before the structure at `offset` could be read.
    #[error("Truncated PE buffer at byte offset {offset:#x}")]
    Truncated { offset: usize },

    /// `IMAGE_DOS_HEADER::e_magic` did not match `0x5A4D` (`"MZ"`).
    #[error("Invalid DOS 'MZ' magic signature: {0:#06x}")]
    InvalidDosMagic(u16),

    /// `IMAGE_DOS_HEADER::e_lfanew` was zero, negative, or pointed outside the file.
    #[error("Invalid or out-of-bounds e_lfanew offset: {0:#010x}")]
    InvalidLfanew(u32),

    /// `IMAGE_NT_HEADERS::Signature` did not match `0x00004550` (`"PE\0\0"`).
    #[error("Invalid PE 'PE\\0\\0' signature: {0:#010x}")]
    InvalidPeSignature(u32),

    /// `IMAGE_OPTIONAL_HEADER::Magic` was neither `0x010B` (PE32) nor `0x020B` (PE32+).
    #[error("Unsupported PE Optional Header magic: {0:#06x}")]
    UnsupportedOptionalHeaderMagic(u16),

    /// A Relative Virtual Address (RVA) did not fall within the raw disk bounds of any section.
    #[error("RVA {rva:#010x} does not map to raw data in any PE section")]
    UnmappedRva { rva: u32 },

    /// An exported symbol or forwarder string was not null-terminated or contained invalid ASCII/UTF-8.
    #[error("Malformed or unterminated string in export directory at file offset {offset:#x}")]
    MalformedExportString { offset: usize },
}

// ============================================================================
// Primitive Byte-Reading Helpers
// ============================================================================

/// Reads a little-endian `u16` from `bytes` at `offset` with overflow-safe bounds checking.
///
/// # Arguments
///
/// * `bytes` - Raw byte slice of the PE file.
/// * `offset` - Starting byte offset to read from.
///
/// # Return values
///
/// * `Ok(u16)` - The decoded 16-bit unsigned integer.
/// * `Err(PeParseError::Truncated)` - `offset..offset + 2` overflows `usize` or exceeds `bytes.len()`.
#[inline]
fn read_u16_le(bytes: &[u8], offset: usize) -> Result<u16, PeParseError> {
    let end = offset
        .checked_add(2)
        .ok_or(PeParseError::Truncated { offset })?;
    let slice = bytes
        .get(offset..end)
        .ok_or(PeParseError::Truncated { offset })?;
    Ok(u16::from_le_bytes(slice.try_into().unwrap()))
}

/// Reads a little-endian `u32` from `bytes` at `offset` with overflow-safe bounds checking.
///
/// # Arguments
///
/// * `bytes` - Raw byte slice of the PE file.
/// * `offset` - Starting byte offset to read from.
///
/// # Return values
///
/// * `Ok(u32)` - The decoded 32-bit unsigned integer.
/// * `Err(PeParseError::Truncated)` - `offset..offset + 4` overflows `usize` or exceeds `bytes.len()`.
#[inline]
fn read_u32_le(bytes: &[u8], offset: usize) -> Result<u32, PeParseError> {
    let end = offset
        .checked_add(4)
        .ok_or(PeParseError::Truncated { offset })?;
    let slice = bytes
        .get(offset..end)
        .ok_or(PeParseError::Truncated { offset })?;
    Ok(u32::from_le_bytes(slice.try_into().unwrap()))
}

/// Reads a null-terminated ASCII/UTF-8 string starting at `offset`, borrowing directly
/// from `bytes` with zero heap allocations.
///
/// # Arguments
///
/// * `bytes` - Raw byte slice of the PE file.
/// * `offset` - File byte offset where the C-string begins.
///
/// # Return values
///
/// * `Ok(&str)` - Borrowed string slice up to (but excluding) the first `\0` byte.
/// * `Err(PeParseError::Truncated)` - `offset` is outside `bytes.len()`.
/// * `Err(PeParseError::MalformedExportString)` - No NUL terminator was found before EOF, or the bytes are not valid UTF-8.
#[inline]
fn read_null_terminated_str(bytes: &[u8], offset: usize) -> Result<&str, PeParseError> {
    let slice = bytes
        .get(offset..)
        .ok_or(PeParseError::Truncated { offset })?;

    let null_pos = slice
        .iter()
        .position(|&b| b == 0)
        .ok_or(PeParseError::MalformedExportString { offset })?;

    std::str::from_utf8(&slice[..null_pos])
        .map_err(|_| PeParseError::MalformedExportString { offset })
}

// ============================================================================
// Core PE Parser Implementation
// ============================================================================

/// Opens and parses a Portable Executable (`.exe` / `.dll`) file from disk.
///
/// Opens the target file with `read(true)` and permissive Win32 sharing flags
/// (`FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE`) so actively mapped system
/// executables and DLLs can be inspected without triggering `ERROR_SHARING_VIOLATION`.
///
/// # Arguments
///
/// * `path` - Filesystem path to the target binary on disk.
///
/// # Return values
///
/// * `Ok(PeMetadata)` - Successfully parsed PE headers and extracted tracked export RVAs.
/// * `Err(PeParseError)` - File could not be opened/read, or its PE headers are malformed.
pub fn parse_pe_file<P: AsRef<Path>>(path: P) -> Result<PeMetadata, PeParseError> {
    // Open with read access and full sharing flags (`READ | WRITE | DELETE`) to avoid
    // sharing violations when inspecting running processes or locked system DLLs.
    let mut file = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .open(path)?;

    // Pre-allocate capacity using file metadata if available to minimize Vec reallocations.
    let initial_cap = file.metadata().map(|m| m.len() as usize).unwrap_or(0);
    let mut bytes = Vec::with_capacity(initial_cap);
    file.read_to_end(&mut bytes)?;

    parse_pe_bytes(bytes.as_slice())
}

/// Parses a Portable Executable image from an in-memory byte slice.
///
/// Orchestrates the four-stage parsing pipeline:
/// 1. [`parse_dos_header`] validates the `"MZ"` signature and locates `e_lfanew`.
/// 2. [`parse_nt_headers`] validates `"PE\0\0"` and parses the File and Optional Headers.
/// 3. [`parse_section_headers`] builds the section table required for RVA-to-file-offset translation.
/// 4. [`parse_export_directory`] walks `.edata` (if present) and extracts [`TrackedExport`] entries.
///
/// # Arguments
///
/// * `bytes` - Complete raw byte slice of the PE file on disk.
///
/// # Return values
///
/// * `Ok(PeMetadata)` - Extracted architectural metadata and tracked export table.
/// * `Err(PeParseError)` - The buffer is truncated or violates the PE format specification.
pub fn parse_pe_bytes(bytes: &[u8]) -> Result<PeMetadata, PeParseError> {
    let lfanew_off = parse_dos_header(bytes)?;
    let nt_info = parse_nt_headers(bytes, lfanew_off)?;
    let sections =
        parse_section_headers(bytes, nt_info.section_table_offset, nt_info.num_sections)?;

    // Only parse the Export Directory if DataDirectory[0] has a non-zero RVA and size.
    let has_exports = nt_info.export_dir_rva != 0 && nt_info.export_dir_size != 0;
    let export_map = if has_exports {
        parse_export_directory(
            bytes,
            nt_info.export_dir_rva,
            nt_info.export_dir_size,
            &sections,
        )?
    } else {
        HashMap::new()
    };

    Ok(PeMetadata {
        architecture: nt_info.architecture,
        is_dll: nt_info.is_dll,
        size_of_image: nt_info.size_of_image,
        entry_point_rva: nt_info.entry_point_rva,
        checksum: nt_info.checksum,
        time_date_stamp: nt_info.time_date_stamp,
        exports: export_map,
    })
}

/// Validates the 64-byte `IMAGE_DOS_HEADER` at offset `0` and extracts the `e_lfanew` offset.
///
/// Rejects files smaller than 64 bytes, files missing the `"MZ"` (`0x5A4D`) magic signature,
/// and corrupt/malicious `e_lfanew` pointers (zero, negative signed values `>= 0x8000_0000`,
/// or offsets pointing past the end of `bytes`).
///
/// # Arguments
///
/// * `bytes` - Raw byte slice of the PE file.
///
/// # Return values
///
/// * `Ok(usize)` - Validated file byte offset (`e_lfanew`) where `IMAGE_NT_HEADERS` begins.
/// * `Err(PeParseError::Truncated)` - Buffer is smaller than `IMAGE_DOS_HEADER_SIZE` (64 bytes).
/// * `Err(PeParseError::InvalidDosMagic)` - First two bytes do not match `0x5A4D` (`"MZ"`).
/// * `Err(PeParseError::InvalidLfanew)` - `e_lfanew` is `0`, negative, or out of bounds.
pub fn parse_dos_header(bytes: &[u8]) -> Result<usize, PeParseError> {
    if bytes.len() < IMAGE_DOS_HEADER_SIZE {
        return Err(PeParseError::Truncated { offset: 0 });
    }

    let magic = read_u16_le(bytes, 0)?;
    if magic != IMAGE_DOS_SIGNATURE {
        return Err(PeParseError::InvalidDosMagic(magic));
    }

    // e_lfanew is a 4-byte offset at 0x3C pointing to the NT Header ("PE\0\0").
    // In the C struct it is a signed LONG (i32), so values >= 0x8000_0000 are negative offsets.
    let e_lfanew_raw = read_u32_le(bytes, DOS_LFANEW_OFFSET)?;
    let e_lfanew = e_lfanew_raw as usize;
    if e_lfanew == 0 || e_lfanew_raw >= 0x8000_0000 || e_lfanew >= bytes.len() {
        return Err(PeParseError::InvalidLfanew(e_lfanew_raw));
    }

    Ok(e_lfanew)
}

/// Parses the `IMAGE_NT_HEADERS` (`Signature`, `IMAGE_FILE_HEADER`, and `IMAGE_OPTIONAL_HEADER`)
/// starting at file offset `lfanew`.
///
/// Handles both 32-bit (`PE32`, magic `0x010B`) and 64-bit (`PE32+`, magic `0x020B`) Optional
/// Headers, accounting for the widened 64-bit fields (`ImageBase`, `SizeOfStackReserve`, etc.)
/// that shift `NumberOfRvaAndSizes` and `DataDirectory[0]` by 16 bytes in `PE32+`.
///
/// # Arguments
///
/// * `bytes` - Raw byte slice of the PE file.
/// * `lfanew` - Byte offset to `IMAGE_NT_HEADERS` obtained from [`parse_dos_header`].
///
/// # Return values
///
/// * `Ok(NtHeaderInfo)` - Extracted header fields, Export Directory RVA/size, and Section Table offset.
/// * `Err(PeParseError::InvalidPeSignature)` - Signature at `lfanew` is not `0x00004550` (`"PE\0\0"`).
/// * `Err(PeParseError::UnsupportedOptionalHeaderMagic)` - Optional Header magic is neither `0x010B` nor `0x020B`.
/// * `Err(PeParseError::Truncated)` - File ends before the File Header or Optional Header completes.
pub fn parse_nt_headers(bytes: &[u8], lfanew: usize) -> Result<NtHeaderInfo, PeParseError> {
    // 1. Validate the 4-byte "PE\0\0" signature at lfanew + 0x00.
    let signature = read_u32_le(bytes, lfanew)?;
    if signature != IMAGE_NT_SIGNATURE {
        return Err(PeParseError::InvalidPeSignature(signature));
    }

    // 2. Parse IMAGE_FILE_HEADER (20 bytes starting at lfanew + 0x04).
    let file_hdr_off = lfanew
        .checked_add(0x04)
        .ok_or(PeParseError::Truncated { offset: lfanew })?;
    let num_sections = read_u16_le(bytes, file_hdr_off + 0x02)?;
    let time_date_stamp = read_u32_le(bytes, file_hdr_off + 0x04)?;
    let size_of_optional_header = read_u16_le(bytes, file_hdr_off + 0x10)?;
    let characteristics = read_u16_le(bytes, file_hdr_off + 0x12)?;

    let is_dll = (characteristics & IMAGE_FILE_DLL) != 0;

    // 3. Validate bounds of IMAGE_OPTIONAL_HEADER (starts at lfanew + 0x18).
    let optional_header_off = lfanew
        .checked_add(0x18)
        .ok_or(PeParseError::Truncated { offset: lfanew })?;
    let section_table_offset = optional_header_off
        .checked_add(size_of_optional_header as usize)
        .ok_or(PeParseError::Truncated {
            offset: optional_header_off,
        })?;

    if section_table_offset > bytes.len() {
        return Err(PeParseError::Truncated {
            offset: optional_header_off,
        });
    }

    // 4. Determine PE32 (32-bit) vs PE32+ (64-bit) from the Optional Header Magic.
    let magic = read_u16_le(bytes, optional_header_off)?;
    let architecture = match magic {
        IMAGE_NT_OPTIONAL_HDR32_MAGIC => PeArchitecture::X86,
        IMAGE_NT_OPTIONAL_HDR64_MAGIC => PeArchitecture::X64,
        _ => return Err(PeParseError::UnsupportedOptionalHeaderMagic(magic)),
    };

    // Common fields that share identical relative offsets in both PE32 and PE32+.
    let entry_point_rva = read_u32_le(bytes, optional_header_off + 0x10)?;
    let size_of_image = read_u32_le(bytes, optional_header_off + 0x38)?;
    let checksum = read_u32_le(bytes, optional_header_off + 0x40)?;

    // In PE32, NumberOfRvaAndSizes is at +0x5C and DataDirectory[0] (Export) is at +0x60..+0x68.
    // In PE32+, four 32-bit fields widen to 64-bit, shifting them by +0x10 to +0x6C and +0x70..+0x78.
    let (num_rva_off, export_dir_off, min_opt_size) = match architecture {
        PeArchitecture::X86 => (0x5C, 0x60, 0x68),
        PeArchitecture::X64 => (0x6C, 0x70, 0x78),
    };

    // Guard against custom/tiny Optional Headers that omit the DataDirectory array.
    let (export_dir_rva, export_dir_size) = if size_of_optional_header >= min_opt_size {
        let num_rva = read_u32_le(bytes, optional_header_off + num_rva_off)?;
        if num_rva >= 1 {
            let rva = read_u32_le(bytes, optional_header_off + export_dir_off)?;
            let size = read_u32_le(bytes, optional_header_off + export_dir_off + 4)?;
            (rva, size)
        } else {
            (0, 0)
        }
    } else {
        (0, 0)
    };

    Ok(NtHeaderInfo {
        architecture,
        is_dll,
        num_sections,
        size_of_image,
        entry_point_rva,
        checksum,
        time_date_stamp,
        export_dir_rva,
        export_dir_size,
        section_table_offset,
    })
}

/// Parses `num_sections` consecutive 40-byte `IMAGE_SECTION_HEADER` entries starting at `section_table_offset`.
///
/// Extracts virtual and raw disk layout bounds for every section so subsequent RVA lookups
/// can map virtual addresses back to raw file offsets.
///
/// # Arguments
///
/// * `bytes` - Raw byte slice of the PE file.
/// * `section_table_offset` - File offset where the first `IMAGE_SECTION_HEADER` begins.
/// * `num_sections` - Number of section headers (`IMAGE_FILE_HEADER::NumberOfSections`).
///
/// # Return values
///
/// * `Ok(Vec<SectionInfo>)` - Ordered list of parsed section descriptors.
/// * `Err(PeParseError::Truncated)` - The section table extends past the end of `bytes`.
pub fn parse_section_headers(
    bytes: &[u8],
    section_table_offset: usize,
    num_sections: u16,
) -> Result<Vec<SectionInfo>, PeParseError> {
    let mut vec_sec_info = Vec::<SectionInfo>::with_capacity(num_sections as usize);

    for i in 0..num_sections as usize {
        // Each IMAGE_SECTION_HEADER is 40 bytes (0x28 in hex, IMAGE_SECTION_HEADER_SIZE).
        let offset = section_table_offset
            .checked_add(IMAGE_SECTION_HEADER_SIZE * i)
            .ok_or(PeParseError::Truncated {
                offset: section_table_offset,
            })?;

        // Ensure the full 40-byte section header is within bounds.
        if offset
            .checked_add(IMAGE_SECTION_HEADER_SIZE)
            .is_none_or(|end| end > bytes.len())
        {
            return Err(PeParseError::Truncated { offset });
        }

        let sec_info = SectionInfo {
            virtual_size: read_u32_le(bytes, offset + 0x08)?,
            virtual_address: read_u32_le(bytes, offset + 0x0C)?,
            raw_data_size: read_u32_le(bytes, offset + 0x10)?,
            raw_data_offset: read_u32_le(bytes, offset + 0x14)?,
            characteristics: read_u32_le(bytes, offset + 0x24)?,
        };

        vec_sec_info.push(sec_info);
    }

    Ok(vec_sec_info)
}

/// Translates a Relative Virtual Address (`rva`) into a raw file byte offset using the parsed section table.
///
/// Because a PE on disk is laid out using `PointerToRawData` alignment rather than virtual memory
/// `SectionAlignment`, any RVA read from data directories (such as the Export Directory) must be
/// resolved against the enclosing section's virtual range and converted via:
/// `file_offset = section.raw_data_offset + (rva - section.virtual_address)`.
///
/// # Arguments
///
/// * `rva` - The Relative Virtual Address to translate.
/// * `sections` - Slice of parsed [`SectionInfo`] headers from [`parse_section_headers`].
///
/// # Return values
///
/// * `Ok(usize)` - Raw byte offset within the on-disk file corresponding to `rva`.
/// * `Err(PeParseError::UnmappedRva)` - `rva` does not fall inside any section, or falls inside
///   a zero-filled `.bss` region (`delta >= section.raw_data_size`) that has no backing bytes on disk.
pub fn rva_to_file_offset(rva: u32, sections: &[SectionInfo]) -> Result<usize, PeParseError> {
    for section in sections {
        let virtual_span = section.virtual_size.max(section.raw_data_size);
        let section_end = section.virtual_address.saturating_add(virtual_span);

        // Check whether this section's virtual address range contains the target RVA.
        if rva >= section.virtual_address && rva < section_end {
            // Compute how many bytes into the section this RVA lies.
            let delta = rva - section.virtual_address;

            // Uninitialized data (.bss) exists in virtual memory (VirtualSize > SizeOfRawData)
            // but occupies 0 bytes on disk. If delta >= raw_data_size, there is no file data to read.
            if delta >= section.raw_data_size {
                return Err(PeParseError::UnmappedRva { rva });
            }

            let file_offset = (section.raw_data_offset as usize)
                .checked_add(delta as usize)
                .ok_or(PeParseError::UnmappedRva { rva })?;
            return Ok(file_offset);
        }
    }

    Err(PeParseError::UnmappedRva { rva })
}

/// Parses the `IMAGE_EXPORT_DIRECTORY` and extracts all exports matching [`TrackedExport`].
///
/// Walks the three parallel export tables (`AddressOfNames`, `AddressOfNameOrdinals`, and
/// `AddressOfFunctions`). To keep parsing fast on large system DLLs like `ntdll.dll` (>2,400 exports)
/// or `kernel32.dll` (>1,600 exports), each exported symbol name is borrowed in-place from the byte
/// slice with zero heap allocations and filtered through [`TrackedExport::from_symbol_name`] before
/// resolving its ordinal and function RVA.
///
/// Automatically detects **Forwarded Exports** (when `func_rva` falls within
/// `[export_dir_rva, export_dir_rva + export_dir_size)`) vs. direct **Code Exports**.
///
/// # Arguments
///
/// * `bytes` - Raw byte slice of the PE file.
/// * `export_dir_rva` - RVA of `IMAGE_EXPORT_DIRECTORY` (`DataDirectory[0].VirtualAddress`).
/// * `export_dir_size` - Byte size of the export directory (`DataDirectory[0].Size`).
/// * `sections` - Parsed section headers used to translate RVAs to file offsets.
///
/// # Return values
///
/// * `Ok(HashMap<TrackedExport, ExportTarget>)` - Map of tracked symbols to their resolved [`ExportTarget`].
/// * `Err(PeParseError)` - Export directory or its internal tables contain unmapped RVAs, truncated buffers, or malformed strings.
pub fn parse_export_directory(
    bytes: &[u8],
    export_dir_rva: u32,
    export_dir_size: u32,
    sections: &[SectionInfo],
) -> Result<HashMap<TrackedExport, ExportTarget>, PeParseError> {
    let export_offset = rva_to_file_offset(export_dir_rva, sections)?;
    if export_offset
        .checked_add(IMAGE_EXPORT_DIRECTORY_SIZE)
        .is_none_or(|end| end > bytes.len())
    {
        return Err(PeParseError::Truncated {
            offset: export_offset,
        });
    }

    // Read table counts and RVAs from the 40-byte IMAGE_EXPORT_DIRECTORY header.
    let number_of_functions = read_u32_le(bytes, export_offset + 0x14)?;
    let number_of_names = read_u32_le(bytes, export_offset + 0x18)?;
    let address_of_functions_rva = read_u32_le(bytes, export_offset + 0x1C)?;
    let address_of_names_rva = read_u32_le(bytes, export_offset + 0x20)?;
    let address_of_name_ordinals_rva = read_u32_le(bytes, export_offset + 0x24)?;

    if number_of_names == 0 || number_of_functions == 0 {
        return Ok(HashMap::new());
    }

    // Translate the base RVAs of the three parallel export arrays into file offsets.
    let functions_offset = rva_to_file_offset(address_of_functions_rva, sections)?;
    let names_offset = rva_to_file_offset(address_of_names_rva, sections)?;
    let ordinals_offset = rva_to_file_offset(address_of_name_ordinals_rva, sections)?;

    let export_dir_end = export_dir_rva.saturating_add(export_dir_size);
    let mut exports = HashMap::new();

    for i in 0..number_of_names as usize {
        //  Read the symbol's name RVA from AddressOfNames[i] (array of u32 RVAs).
        let name_entry_offset = names_offset
            .checked_add(i * 4)
            .ok_or(PeParseError::Truncated {
                offset: names_offset,
            })?;
        let name_rva = read_u32_le(bytes, name_entry_offset)?;
        let name_file_offset = rva_to_file_offset(name_rva, sections)?;
        let symbol_name = read_null_terminated_str(bytes, name_file_offset)?;

        // Filter against TrackedExport before touching ordinals or function RVAs.
        let Some(tracked) = TrackedExport::from_symbol_name(symbol_name) else {
            continue;
        };

        // 3. Read the 0-based EAT index from AddressOfNameOrdinals[i] (array of u16 indices).
        let ord_entry_offset =
            ordinals_offset
                .checked_add(i * 2)
                .ok_or(PeParseError::Truncated {
                    offset: ordinals_offset,
                })?;
        let ordinal_index = read_u16_le(bytes, ord_entry_offset)? as usize;
        if ordinal_index >= number_of_functions as usize {
            continue; // Corrupt ordinal index; skip safely.
        }

        // Read the target RVA from AddressOfFunctions[ordinal_index] (array of u32 RVAs).
        let func_entry_offset =
            functions_offset
                .checked_add(ordinal_index * 4)
                .ok_or(PeParseError::Truncated {
                    offset: functions_offset,
                })?;
        let func_rva = read_u32_le(bytes, func_entry_offset)?;

        // Distinguish Forwarded Exports (RVA points inside the Export Directory itself)
        // from direct Code RVAs (RVA points to executable section outside .edata).
        let target = if func_rva >= export_dir_rva && func_rva < export_dir_end {
            let fwd_offset = rva_to_file_offset(func_rva, sections)?;
            let fwd_str = read_null_terminated_str(bytes, fwd_offset)?;
            ExportTarget::Forwarded(fwd_str.to_string())
        } else {
            ExportTarget::CodeRva(func_rva)
        };

        exports.insert(tracked, target);
    }

    Ok(exports)
}

// ============================================================================
// Unit & Integration Test Suite
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper that builds a synthetic PE32 (32-bit) or PE32+ (64-bit) image in memory
    /// with a `.text` section (`RVA 0x1000`, `RawOffset 0x200`, `Size 0x200`) and an
    /// `.edata` section (`RVA 0x2000`, `RawOffset 0x400`, `Size 0x200`) containing custom exports.
    fn build_synthetic_pe(
        is_64bit: bool,
        is_dll: bool,
        exports: &[(&str, u32, Option<&str>)], // (symbol_name, code_rva, optional_forwarder_target)
    ) -> Vec<u8> {
        let mut buf = vec![0u8; 0x600];

        // 1. DOS Header at 0x00
        buf[0..2].copy_from_slice(&IMAGE_DOS_SIGNATURE.to_le_bytes());
        let lfanew: u32 = 0x40;
        buf[DOS_LFANEW_OFFSET..DOS_LFANEW_OFFSET + 4].copy_from_slice(&lfanew.to_le_bytes());

        // 2. NT Headers at 0x40
        let nt = lfanew as usize;
        buf[nt..nt + 4].copy_from_slice(&IMAGE_NT_SIGNATURE.to_le_bytes());

        // IMAGE_FILE_HEADER (20 bytes at nt + 4)
        let fh = nt + 4;
        let machine: u16 = if is_64bit { 0x8664 } else { 0x014C };
        let num_sections: u16 = 2;
        let time_date_stamp: u32 = 0x6543_2100;
        let opt_hdr_size: u16 = if is_64bit { 0xF0 } else { 0xE0 };
        let characteristics: u16 = 0x0002 | if is_dll { IMAGE_FILE_DLL } else { 0 };

        buf[fh..fh + 2].copy_from_slice(&machine.to_le_bytes());
        buf[fh + 2..fh + 4].copy_from_slice(&num_sections.to_le_bytes());
        buf[fh + 4..fh + 8].copy_from_slice(&time_date_stamp.to_le_bytes());
        buf[fh + 16..fh + 18].copy_from_slice(&opt_hdr_size.to_le_bytes());
        buf[fh + 18..fh + 20].copy_from_slice(&characteristics.to_le_bytes());

        // IMAGE_OPTIONAL_HEADER at nt + 24 (0x58)
        let opt = nt + 24;
        let magic: u16 = if is_64bit {
            IMAGE_NT_OPTIONAL_HDR64_MAGIC
        } else {
            IMAGE_NT_OPTIONAL_HDR32_MAGIC
        };
        let entry_point_rva: u32 = 0x1040;
        let size_of_image: u32 = 0x3000;
        let checksum: u32 = 0x00AB_CDEF;

        buf[opt..opt + 2].copy_from_slice(&magic.to_le_bytes());
        buf[opt + 0x10..opt + 0x14].copy_from_slice(&entry_point_rva.to_le_bytes());
        buf[opt + 0x38..opt + 0x3C].copy_from_slice(&size_of_image.to_le_bytes());
        buf[opt + 0x40..opt + 0x44].copy_from_slice(&checksum.to_le_bytes());

        let (num_rva_offset, export_dir_entry_offset) = if is_64bit {
            (opt + 0x6C, opt + 0x70)
        } else {
            (opt + 0x5C, opt + 0x60)
        };
        buf[num_rva_offset..num_rva_offset + 4].copy_from_slice(&16u32.to_le_bytes());

        let export_dir_rva: u32 = if exports.is_empty() { 0 } else { 0x2000 };
        let export_dir_size: u32 = if exports.is_empty() { 0 } else { 0x0180 };
        buf[export_dir_entry_offset..export_dir_entry_offset + 4]
            .copy_from_slice(&export_dir_rva.to_le_bytes());
        buf[export_dir_entry_offset + 4..export_dir_entry_offset + 8]
            .copy_from_slice(&export_dir_size.to_le_bytes());

        // 3. Section Headers at opt + opt_hdr_size
        let sec0 = opt + (opt_hdr_size as usize);
        // Section 0: .text (RVA 0x1000, VirtualSize 0x180, RawOffset 0x200, RawSize 0x200)
        buf[sec0..sec0 + 8].copy_from_slice(b".text\0\0\0");
        buf[sec0 + 0x08..sec0 + 0x0C].copy_from_slice(&0x0180u32.to_le_bytes());
        buf[sec0 + 0x0C..sec0 + 0x10].copy_from_slice(&0x1000u32.to_le_bytes());
        buf[sec0 + 0x10..sec0 + 0x14].copy_from_slice(&0x0200u32.to_le_bytes());
        buf[sec0 + 0x14..sec0 + 0x18].copy_from_slice(&0x0200u32.to_le_bytes());
        buf[sec0 + 0x24..sec0 + 0x28].copy_from_slice(&0x6000_0020u32.to_le_bytes());

        // Section 1: .edata (RVA 0x2000, VirtualSize 0x200, RawOffset 0x400, RawSize 0x200)
        let sec1 = sec0 + IMAGE_SECTION_HEADER_SIZE;
        buf[sec1..sec1 + 8].copy_from_slice(b".edata\0\0");
        buf[sec1 + 0x08..sec1 + 0x0C].copy_from_slice(&0x0200u32.to_le_bytes());
        buf[sec1 + 0x0C..sec1 + 0x10].copy_from_slice(&0x2000u32.to_le_bytes());
        buf[sec1 + 0x10..sec1 + 0x14].copy_from_slice(&0x0200u32.to_le_bytes());
        buf[sec1 + 0x14..sec1 + 0x18].copy_from_slice(&0x0400u32.to_le_bytes());
        buf[sec1 + 0x24..sec1 + 0x28].copy_from_slice(&0x4000_0040u32.to_le_bytes());

        if exports.is_empty() {
            return buf;
        }

        // 4. Populate .edata at file offset 0x400 (RVA 0x2000)
        let edata_file = 0x400usize;
        let edata_rva = 0x2000u32;
        let count = exports.len() as u32;

        // Layout inside .edata:
        // +0x00 (40B): IMAGE_EXPORT_DIRECTORY
        // +0x28: AddressOfFunctions (count * 4)
        // +0x28 + count*4: AddressOfNames (count * 4)
        // +0x28 + count*8: AddressOfNameOrdinals (count * 2)
        // +0x80: String pool for symbol names and forwarder strings
        let funcs_rel = 0x28u32;
        let names_rel = funcs_rel + count * 4;
        let ords_rel = names_rel + count * 4;
        let mut str_cursor = 0x80usize;

        buf[edata_file + 0x10..edata_file + 0x14].copy_from_slice(&1u32.to_le_bytes()); // Base = 1
        buf[edata_file + 0x14..edata_file + 0x18].copy_from_slice(&count.to_le_bytes()); // NumberOfFunctions
        buf[edata_file + 0x18..edata_file + 0x1C].copy_from_slice(&count.to_le_bytes()); // NumberOfNames
        buf[edata_file + 0x1C..edata_file + 0x20]
            .copy_from_slice(&(edata_rva + funcs_rel).to_le_bytes());
        buf[edata_file + 0x20..edata_file + 0x24]
            .copy_from_slice(&(edata_rva + names_rel).to_le_bytes());
        buf[edata_file + 0x24..edata_file + 0x28]
            .copy_from_slice(&(edata_rva + ords_rel).to_le_bytes());

        for (i, (sym_name, code_rva, forwarder)) in exports.iter().enumerate() {
            // Write symbol name into string pool
            let name_rva = edata_rva + (str_cursor as u32);
            let name_bytes = sym_name.as_bytes();
            buf[edata_file + str_cursor..edata_file + str_cursor + name_bytes.len()]
                .copy_from_slice(name_bytes);
            buf[edata_file + str_cursor + name_bytes.len()] = 0;
            str_cursor += name_bytes.len() + 1;

            // Write AddressOfNames[i] and AddressOfNameOrdinals[i]
            let name_entry_off = edata_file + (names_rel as usize) + i * 4;
            buf[name_entry_off..name_entry_off + 4].copy_from_slice(&name_rva.to_le_bytes());

            let ord_entry_off = edata_file + (ords_rel as usize) + i * 2;
            buf[ord_entry_off..ord_entry_off + 2].copy_from_slice(&(i as u16).to_le_bytes());

            // Write AddressOfFunctions[i] (either direct code RVA or forwarder string RVA inside .edata)
            let func_rva = if let Some(fwd_str) = forwarder {
                let fwd_rva = edata_rva + (str_cursor as u32);
                let fwd_bytes = fwd_str.as_bytes();
                buf[edata_file + str_cursor..edata_file + str_cursor + fwd_bytes.len()]
                    .copy_from_slice(fwd_bytes);
                buf[edata_file + str_cursor + fwd_bytes.len()] = 0;
                str_cursor += fwd_bytes.len() + 1;
                fwd_rva
            } else {
                *code_rva
            };

            let func_entry_off = edata_file + (funcs_rel as usize) + i * 4;
            buf[func_entry_off..func_entry_off + 4].copy_from_slice(&func_rva.to_le_bytes());
        }

        buf
    }

    // ------------------------------------------------------------------------
    // 1. TrackedExport Mapping Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_tracked_export_symbol_roundtrip() {
        let cases = [
            ("LoadLibraryA", TrackedExport::LoadLibraryA),
            ("LoadLibraryW", TrackedExport::LoadLibraryW),
            ("LoadLibraryExA", TrackedExport::LoadLibraryExA),
            ("LoadLibraryExW", TrackedExport::LoadLibraryExW),
            ("LdrLoadDll", TrackedExport::LdrLoadDll),
        ];

        for (name, expected_variant) in cases {
            assert_eq!(
                TrackedExport::from_symbol_name(name),
                Some(expected_variant),
                "Expected '{name}' to map to {expected_variant:?}"
            );
            assert_eq!(
                expected_variant.symbol_name(),
                name,
                "Canonical symbol_name() must round-trip back to '{name}'"
            );
        }

        // Case-sensitive & untracked symbols must return None
        assert_eq!(TrackedExport::from_symbol_name("loadlibraryw"), None);
        assert_eq!(TrackedExport::from_symbol_name("Sleep"), None);
        assert_eq!(TrackedExport::from_symbol_name(""), None);
    }

    // ------------------------------------------------------------------------
    // 2. DOS Header Validation Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_dos_header_validation() {
        // Buffer smaller than 64 bytes -> Truncated
        let short_buf = [0u8; 32];
        assert!(matches!(
            parse_dos_header(&short_buf),
            Err(PeParseError::Truncated { offset: 0 })
        ));

        // Bad DOS magic -> InvalidDosMagic
        let mut bad_magic = [0u8; 64];
        bad_magic[0..2].copy_from_slice(&0x1234u16.to_le_bytes());
        assert!(matches!(
            parse_dos_header(&bad_magic),
            Err(PeParseError::InvalidDosMagic(0x1234))
        ));

        // e_lfanew = 0 or out of bounds -> InvalidLfanew
        let mut zero_lfanew = [0u8; 64];
        zero_lfanew[0..2].copy_from_slice(&IMAGE_DOS_SIGNATURE.to_le_bytes());
        zero_lfanew[DOS_LFANEW_OFFSET..DOS_LFANEW_OFFSET + 4].copy_from_slice(&0u32.to_le_bytes());
        assert!(matches!(
            parse_dos_header(&zero_lfanew),
            Err(PeParseError::InvalidLfanew(0))
        ));

        let mut oob_lfanew = [0u8; 64];
        oob_lfanew[0..2].copy_from_slice(&IMAGE_DOS_SIGNATURE.to_le_bytes());
        oob_lfanew[DOS_LFANEW_OFFSET..DOS_LFANEW_OFFSET + 4]
            .copy_from_slice(&0x1000u32.to_le_bytes());
        assert!(matches!(
            parse_dos_header(&oob_lfanew),
            Err(PeParseError::InvalidLfanew(0x1000))
        ));

        // Valid DOS header
        let pe = build_synthetic_pe(true, true, &[]);
        assert_eq!(parse_dos_header(&pe).expect("Valid DOS header"), 0x40);
    }

    // ------------------------------------------------------------------------
    // 3. NT Headers (PE32 & PE32+) Validation Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_nt_headers_validation_and_architectures() {
        // Bad PE signature
        let mut bad_pe_sig = build_synthetic_pe(true, true, &[]);
        bad_pe_sig[0x40..0x44].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        assert!(matches!(
            parse_nt_headers(&bad_pe_sig, 0x40),
            Err(PeParseError::InvalidPeSignature(0xDEAD_BEEF))
        ));

        // Unsupported Optional Header Magic
        let mut bad_opt_magic = build_synthetic_pe(true, true, &[]);
        bad_opt_magic[0x58..0x5A].copy_from_slice(&0x0107u16.to_le_bytes()); // ROM image magic
        assert!(matches!(
            parse_nt_headers(&bad_opt_magic, 0x40),
            Err(PeParseError::UnsupportedOptionalHeaderMagic(0x0107))
        ));

        // Valid 32-bit (PE32) EXE
        let pe32 = build_synthetic_pe(false, false, &[("LoadLibraryA", 0x1080, None)]);
        let info32 = parse_nt_headers(&pe32, 0x40).expect("Valid PE32 NT headers");
        assert_eq!(info32.architecture, PeArchitecture::X86);
        assert!(!info32.is_dll);
        assert_eq!(info32.num_sections, 2);
        assert_eq!(info32.entry_point_rva, 0x1040);
        assert_eq!(info32.size_of_image, 0x3000);
        assert_eq!(info32.checksum, 0x00AB_CDEF);
        assert_eq!(info32.time_date_stamp, 0x6543_2100);
        assert_eq!(info32.export_dir_rva, 0x2000);
        assert_eq!(info32.export_dir_size, 0x0180);

        // Valid 64-bit (PE32+) DLL
        let pe64 = build_synthetic_pe(true, true, &[("LdrLoadDll", 0x1100, None)]);
        let info64 = parse_nt_headers(&pe64, 0x40).expect("Valid PE32+ NT headers");
        assert_eq!(info64.architecture, PeArchitecture::X64);
        assert!(info64.is_dll);
        assert_eq!(info64.export_dir_rva, 0x2000);
    }

    // ------------------------------------------------------------------------
    // 4. Section Parsing & RVA-to-File-Offset Translation Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_rva_to_file_offset_translation_and_bss_bounds() {
        let sections = vec![
            SectionInfo {
                virtual_size: 0x1000, // 4096 bytes in virtual memory
                virtual_address: 0x1000,
                raw_data_size: 0x0400, // Only 1024 bytes exist on disk! (Remaining 0xC00 is zero-filled BSS)
                raw_data_offset: 0x0200,
                characteristics: 0x6000_0020,
            },
            SectionInfo {
                virtual_size: 0x0200,
                virtual_address: 0x3000,
                raw_data_size: 0x0200,
                raw_data_offset: 0x0600,
                characteristics: 0x4000_0040,
            },
        ];

        // Exact start of Section 0 (0x1000 -> 0x0200)
        assert_eq!(rva_to_file_offset(0x1000, &sections).unwrap(), 0x0200);

        // Inside initialized raw data of Section 0 (0x13FF -> 0x05FF)
        assert_eq!(rva_to_file_offset(0x13FF, &sections).unwrap(), 0x05FF);

        // Inside virtual span of Section 0, but past SizeOfRawData (BSS uninitialized region: 0x1400)
        assert!(matches!(
            rva_to_file_offset(0x1400, &sections),
            Err(PeParseError::UnmappedRva { rva: 0x1400 })
        ));

        // Unmapped gap between Section 0 and Section 1 (0x2500)
        assert!(matches!(
            rva_to_file_offset(0x2500, &sections),
            Err(PeParseError::UnmappedRva { rva: 0x2500 })
        ));

        // Inside Section 1 (0x3050 -> 0x0650)
        assert_eq!(rva_to_file_offset(0x3050, &sections).unwrap(), 0x0650);
    }

    // ------------------------------------------------------------------------
    // 5. Synthetic Export Directory & Forwarder Resolution Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_parse_synthetic_pe64_exports_and_forwarders() {
        let pe_bytes = build_synthetic_pe(
            true,
            true,
            &[
                ("UntrackedFunction", 0x1010, None),
                ("LoadLibraryW", 0x1050, None),
                ("LdrLoadDll", 0x1090, None),
                // Forwarded export: RVA points inside the .edata export directory
                ("LoadLibraryExW", 0, Some("KERNELBASE.LoadLibraryExW")),
            ],
        );

        let meta = parse_pe_bytes(&pe_bytes).expect("Synthetic PE64 should parse cleanly");
        assert_eq!(meta.architecture, PeArchitecture::X64);
        assert!(meta.is_dll);
        assert_eq!(
            meta.exports.len(),
            3,
            "Only tracked exports should be stored"
        );

        // Direct code RVAs
        assert_eq!(
            meta.get_export(TrackedExport::LoadLibraryW),
            Some(&ExportTarget::CodeRva(0x1050))
        );
        assert_eq!(meta.export_rva(TrackedExport::LoadLibraryW), Some(0x1050));
        assert_eq!(meta.export_rva(TrackedExport::LdrLoadDll), Some(0x1090));

        // Forwarded export
        let ex_w = meta
            .get_export(TrackedExport::LoadLibraryExW)
            .expect("LoadLibraryExW should be present");
        assert!(ex_w.is_forwarded());
        assert_eq!(ex_w.code_rva(), None);
        assert_eq!(ex_w.forwarded_to(), Some("KERNELBASE.LoadLibraryExW"));
    }

    // ------------------------------------------------------------------------
    // 6. Live Windows System32 DLL Verification (Disk RVA == Live Loader RVA)
    // ------------------------------------------------------------------------

    #[test]
    fn test_real_system32_ntdll_and_kernel32_exports_match_os_loader() {
        use windows_sys::{
            Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress},
            w,
        };

        // 1. Parse C:\Windows\System32\ntdll.dll from disk
        let ntdll_path = Path::new("C:\\Windows\\System32\\ntdll.dll");
        let ntdll_meta = parse_pe_file(ntdll_path).expect("Must parse system32\\ntdll.dll");
        assert_eq!(ntdll_meta.architecture, PeArchitecture::X64);
        assert!(ntdll_meta.is_dll);

        let parsed_ldr_rva = ntdll_meta
            .export_rva(TrackedExport::LdrLoadDll)
            .expect("ntdll.dll must export LdrLoadDll as a direct code RVA");

        // Compare our parsed RVA against the live OS loader's address in our process!
        unsafe {
            let h_ntdll = GetModuleHandleW(w!("ntdll.dll"));
            assert!(!h_ntdll.is_null(), "ntdll.dll must be loaded");
            let fn_ldr = GetProcAddress(h_ntdll, c"LdrLoadDll".as_ptr().cast())
                .expect("GetProcAddress(LdrLoadDll) must succeed");
            let live_ldr_rva = ((fn_ldr as usize) - (h_ntdll as usize)) as u32;

            assert_eq!(
                parsed_ldr_rva, live_ldr_rva,
                "Parsed LdrLoadDll RVA from disk ({parsed_ldr_rva:#x}) must exactly match live Windows loader RVA ({live_ldr_rva:#x})"
            );
        }

        // 2. Parse C:\Windows\System32\kernel32.dll from disk
        let k32_path = Path::new("C:\\Windows\\System32\\kernel32.dll");
        let k32_meta = parse_pe_file(k32_path).expect("Must parse system32\\kernel32.dll");
        assert_eq!(k32_meta.architecture, PeArchitecture::X64);
        assert!(k32_meta.is_dll);

        for tracked in [
            TrackedExport::LoadLibraryA,
            TrackedExport::LoadLibraryW,
            TrackedExport::LoadLibraryExA,
            TrackedExport::LoadLibraryExW,
        ] {
            let export = k32_meta
                .get_export(tracked)
                .unwrap_or_else(|| panic!("kernel32.dll must contain tracked export {tracked:?}"));

            // If it's a direct code stub in kernel32.dll (not forwarded), verify its RVA matches GetProcAddress
            if let ExportTarget::CodeRva(parsed_rva) = export {
                assert!(*parsed_rva > 0);
                unsafe {
                    let h_k32 = GetModuleHandleW(w!("kernel32.dll"));
                    let sym_cstr = std::ffi::CString::new(tracked.symbol_name()).unwrap();
                    if let Some(fn_ptr) = GetProcAddress(h_k32, sym_cstr.as_ptr().cast()) {
                        let fn_addr = fn_ptr as usize;
                        let base_addr = h_k32 as usize;
                        // Only compare if GetProcAddress resolved inside kernel32.dll's own image bounds
                        if fn_addr >= base_addr
                            && fn_addr < base_addr + (k32_meta.size_of_image as usize)
                        {
                            let live_rva = (fn_addr - base_addr) as u32;
                            assert_eq!(
                                *parsed_rva, live_rva,
                                "Parsed {:?} RVA ({:#x}) must match live kernel32 RVA ({:#x})",
                                tracked, parsed_rva, live_rva
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn test_real_syswow64_32bit_ntdll_if_present() {
        let wow64_ntdll = Path::new("C:\\Windows\\SysWOW64\\ntdll.dll");
        if wow64_ntdll.exists() {
            let meta = parse_pe_file(wow64_ntdll).expect("Must parse 32-bit SysWOW64\\ntdll.dll");
            assert_eq!(meta.architecture, PeArchitecture::X86);
            assert!(meta.is_dll);
            assert!(
                meta.export_rva(TrackedExport::LdrLoadDll).is_some(),
                "32-bit SysWOW64 ntdll.dll must also export LdrLoadDll"
            );
        }
    }
}
