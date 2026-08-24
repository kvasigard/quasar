//! Portable Executable (PE) domain metadata models and export structures.

use std::collections::HashMap;

/// Machine architecture identifiers from the COFF File Header.
pub mod machine {
    /// Intel 386 (32-bit x86).
    pub const IMAGE_FILE_MACHINE_I386: u16 = 0x014c;
    /// AMD64 (x64 / 64-bit x86).
    pub const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
    /// ARM little endian.
    pub const IMAGE_FILE_MACHINE_ARM: u16 = 0x01c0;
    /// ARM64 little endian.
    pub const IMAGE_FILE_MACHINE_ARM64: u16 = 0xaa64;
}

/// Optional header magic constants.
pub mod magic {
    /// Standard 32-bit PE32 image.
    pub const PE32: u16 = 0x010b;
    /// 64-bit PE32+ (PE32 Plus) image.
    pub const PE32_PLUS: u16 = 0x020b;
    /// ROM image.
    pub const ROM: u16 = 0x0107;
}

/// Section characteristics flags.
pub mod section_flags {
    /// Section contains executable code.
    pub const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
    /// Section can be read.
    pub const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
    /// Section can be written to.
    pub const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;
}

/// Characteristic flags from the COFF File Header.
pub mod file_flags {
    /// File is a dynamic-link library (DLL).
    pub const IMAGE_FILE_DLL: u16 = 0x2000;
    /// File is executable (e.g. no unresolved externals).
    pub const IMAGE_FILE_EXECUTABLE_IMAGE: u16 = 0x0002;
    /// Application can handle > 2GB addresses.
    pub const IMAGE_FILE_LARGE_ADDRESS_AWARE: u16 = 0x0020;
}

/// Metadata representing a single section in the PE image (`IMAGE_SECTION_HEADER`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeSection {
    /// 8-byte section name decoded as UTF-8 / ASCII (e.g. `".text"`, `".data"`, `".rdata"`).
    pub name: String,
    /// Relative Virtual Address (RVA) where the section is loaded in memory.
    pub virtual_address: u32,
    /// Total size of the section when loaded into virtual memory.
    pub virtual_size: u32,
    /// File offset to the raw section data on disk.
    pub raw_data_offset: u32,
    /// Size of the section's data on disk.
    pub raw_data_size: u32,
    /// Section characteristics and permission flags.
    pub characteristics: u32,
}

impl PeSection {
    /// Returns `true` if the section contains executable code (`IMAGE_SCN_MEM_EXECUTE`).
    #[inline]
    pub fn is_executable(&self) -> bool {
        (self.characteristics & section_flags::IMAGE_SCN_MEM_EXECUTE) != 0
    }

    /// Returns `true` if the section is marked as readable (`IMAGE_SCN_MEM_READ`).
    #[inline]
    pub fn is_readable(&self) -> bool {
        (self.characteristics & section_flags::IMAGE_SCN_MEM_READ) != 0
    }

    /// Returns `true` if the section is marked as writable (`IMAGE_SCN_MEM_WRITE`).
    #[inline]
    pub fn is_writable(&self) -> bool {
        (self.characteristics & section_flags::IMAGE_SCN_MEM_WRITE) != 0
    }
}

/// Represents an individual function or variable exported by the PE binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeExport {
    /// Exported symbol name (if exported by name).
    pub name: Option<String>,
    /// Export ordinal number (bias + table index).
    pub ordinal: u16,
    /// Relative Virtual Address (RVA) of the function entrypoint within the PE image.
    pub rva: u32,
    /// Forwarder string if this export forwards to another library (e.g. `"NTDLL.RtlAllocateHeap"`).
    pub forwarder: Option<String>,
}

/// Metadata and index structures representing the PE Export Directory (`IMAGE_DIRECTORY_ENTRY_EXPORT`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PeExportDirectory {
    /// Internal DLL name string referenced in the export directory.
    pub dll_name: Option<String>,
    /// RVA of the export table data directory.
    pub export_table_rva: u32,
    /// Size of the export table in bytes.
    pub export_table_size: u32,
    /// Ordinal base number (bias, typically 1).
    pub ordinal_base: u32,
    /// All exported symbols and stubs.
    pub exports: Vec<PeExport>,
    /// Fast $O(1)$ lookup index: Symbol Name $\rightarrow$ Function RVA.
    pub by_name: HashMap<String, u32>,
    /// Fast $O(1)$ lookup index: Ordinal $\rightarrow$ Function RVA.
    pub by_ordinal: HashMap<u16, u32>,
}

impl PeExportDirectory {
    /// Finds a function's entrypoint RVA by its exported name.
    ///
    /// # Arguments
    ///
    /// * `name` - The function name (case-sensitive as per PE spec, or matched exactly).
    ///
    /// # Returns
    ///
    /// The Relative Virtual Address (RVA) if found, or `None`.
    #[inline]
    pub fn find_rva_by_name(&self, name: &str) -> Option<u32> {
        self.by_name.get(name).copied()
    }

    /// Finds a function's entrypoint RVA by its ordinal number.
    ///
    /// # Arguments
    ///
    /// * `ordinal` - The export ordinal.
    ///
    /// # Returns
    ///
    /// The Relative Virtual Address (RVA) if found, or `None`.
    #[inline]
    pub fn find_rva_by_ordinal(&self, ordinal: u16) -> Option<u32> {
        self.by_ordinal.get(&ordinal).copied()
    }

    /// Looks up a [`PeExport`] record by its function RVA.
    ///
    /// # Arguments
    ///
    /// * `rva` - The Relative Virtual Address to match.
    ///
    /// # Returns
    ///
    /// A reference to the [`PeExport`] if found.
    pub fn find_export_by_rva(&self, rva: u32) -> Option<&PeExport> {
        self.exports.iter().find(|e| e.rva == rva)
    }
}

/// Comprehensive, pure-Rust metadata container extracted from a Portable Executable (PE) binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeInfo {
    /// Whether the binary is 64-bit PE32+ (`true`) or 32-bit PE32 (`false`).
    pub is_64bit: bool,
    /// Target machine CPU architecture (e.g. AMD64 `0x8664`, i386 `0x014C`, ARM64 `0xAA64`).
    pub machine: u16,
    /// COFF characteristics flags.
    pub characteristics: u16,
    /// Target Windows subsystem (e.g. Windows GUI `2`, Windows CUI/Console `3`, Native `1`).
    pub subsystem: u16,
    /// Preferred virtual image base address when loaded into memory.
    pub image_base: u64,
    /// Total virtual memory size required to map all headers and sections.
    pub size_of_image: u32,
    /// Entry point Relative Virtual Address (AddressOfEntryPoint).
    pub entry_point_rva: u32,
    /// Size of all headers (DOS + NT + Section Headers) rounded to file alignment.
    pub size_of_headers: u32,
    /// List of mapped image sections.
    pub sections: Vec<PeSection>,
    /// Parsed Export Directory if the image exports functions or variables.
    pub exports: Option<PeExportDirectory>,
}

impl PeInfo {
    /// Returns `true` if the binary is marked as a Dynamic Link Library (DLL).
    #[inline]
    pub fn is_dll(&self) -> bool {
        (self.characteristics & file_flags::IMAGE_FILE_DLL) != 0
    }

    /// Returns `true` if the binary is marked as an executable image.
    #[inline]
    pub fn is_executable_image(&self) -> bool {
        (self.characteristics & file_flags::IMAGE_FILE_EXECUTABLE_IMAGE) != 0
    }

    /// Finds the entrypoint RVA of an exported function by name.
    #[inline]
    pub fn find_export_by_name(&self, name: &str) -> Option<u32> {
        self.exports.as_ref()?.find_rva_by_name(name)
    }

    /// Finds the [`PeExport`] record matching the specified RVA.
    #[inline]
    pub fn find_export_by_rva(&self, rva: u32) -> Option<&PeExport> {
        self.exports.as_ref()?.find_export_by_rva(rva)
    }

    /// Resolves which section contains a given Relative Virtual Address (RVA).
    pub fn find_section_by_rva(&self, rva: u32) -> Option<&PeSection> {
        self.sections.iter().find(|sec| {
            let span = sec.virtual_size.max(sec.raw_data_size);
            rva >= sec.virtual_address && rva < sec.virtual_address.saturating_add(span)
        })
    }
}
