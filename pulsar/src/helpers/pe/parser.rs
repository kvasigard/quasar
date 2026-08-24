//! Pure-Rust Portable Executable (PE) header parser and export directory extractor.

use std::collections::HashMap;
use std::path::Path;

use super::error::PeError;
use super::models::{PeExport, PeExportDirectory, PeInfo, PeSection, magic};

/// Pure-Rust, memory-safe parser for Windows Portable Executable (PE) 32-bit and 64-bit binaries.
pub struct PeParser;

impl PeParser {
    /// Parses a PE binary from a raw in-memory byte slice.
    ///
    /// Performs defensive validation on the DOS header, NT signature, Optional header,
    /// section table, and Export Directory without allocating external C structures.
    ///
    /// # Arguments
    ///
    /// * `data` - Raw bytes of the PE binary.
    ///
    /// # Returns
    ///
    /// An initialized [`PeInfo`] container describing the binary metadata and exports.
    ///
    /// # Errors
    ///
    /// Returns [`PeError`] if the buffer is truncated, has invalid signatures, or contains
    /// corrupted section bounds.
    pub fn parse(data: &[u8]) -> Result<PeInfo, PeError> {
        const DOS_HEADER_SIZE: usize = 64;
        if data.len() < DOS_HEADER_SIZE {
            return Err(PeError::BufferTooSmall {
                expected: DOS_HEADER_SIZE,
                actual: data.len(),
            });
        }

        // 1. Validate DOS Header ("MZ" / 0x5A4D)
        if data[0] != b'M' || data[1] != b'Z' {
            return Err(PeError::InvalidDosSignature);
        }

        // e_lfanew offset to NT Headers is at offset 0x3C (60)
        let e_lfanew = u32::from_le_bytes(data[0x3C..0x40].try_into().unwrap()) as usize;
        const MIN_NT_HEADERS_SIZE: usize = 24; // 4B signature + 20B COFF header
        if e_lfanew.saturating_add(MIN_NT_HEADERS_SIZE) > data.len() {
            return Err(PeError::InvalidPeHeaderOffset(e_lfanew));
        }

        // 2. Validate NT Signature ("PE\0\0" / 0x00004550)
        if &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
            return Err(PeError::InvalidPeSignature);
        }

        // 3. Parse COFF File Header (20 bytes immediately following "PE\0\0")
        let coff_offset = e_lfanew + 4;
        let machine = u16::from_le_bytes(data[coff_offset..coff_offset + 2].try_into().unwrap());
        let number_of_sections =
            u16::from_le_bytes(data[coff_offset + 2..coff_offset + 4].try_into().unwrap());
        let size_of_optional_header =
            u16::from_le_bytes(data[coff_offset + 16..coff_offset + 18].try_into().unwrap())
                as usize;
        let characteristics =
            u16::from_le_bytes(data[coff_offset + 18..coff_offset + 20].try_into().unwrap());

        // 4. Parse Optional Header
        let opt_offset = coff_offset + 20;
        if opt_offset.saturating_add(size_of_optional_header) > data.len() {
            return Err(PeError::BufferTooSmall {
                expected: opt_offset + size_of_optional_header,
                actual: data.len(),
            });
        }

        if size_of_optional_header < 2 {
            return Err(PeError::UnsupportedOptionalHeaderMagic(0));
        }

        let opt_magic = u16::from_le_bytes(data[opt_offset..opt_offset + 2].try_into().unwrap());
        let (is_64bit, entry_point_rva, image_base, size_of_image, size_of_headers, subsystem, export_rva, export_size) =
            match opt_magic {
                magic::PE32_PLUS => {
                    // 64-bit PE32+ Optional Header
                    const MIN_OPT64_SIZE: usize = 112;
                    if size_of_optional_header < MIN_OPT64_SIZE {
                        return Err(PeError::BufferTooSmall {
                            expected: MIN_OPT64_SIZE,
                            actual: size_of_optional_header,
                        });
                    }

                    let entry_point =
                        u32::from_le_bytes(data[opt_offset + 16..opt_offset + 20].try_into().unwrap());
                    let img_base =
                        u64::from_le_bytes(data[opt_offset + 24..opt_offset + 32].try_into().unwrap());
                    let img_size =
                        u32::from_le_bytes(data[opt_offset + 56..opt_offset + 60].try_into().unwrap());
                    let hdr_size =
                        u32::from_le_bytes(data[opt_offset + 60..opt_offset + 64].try_into().unwrap());
                    let sub_sys =
                        u16::from_le_bytes(data[opt_offset + 68..opt_offset + 70].try_into().unwrap());
                    let num_rva_sizes =
                        u32::from_le_bytes(data[opt_offset + 108..opt_offset + 112].try_into().unwrap());

                    let (exp_rva, exp_size) = if num_rva_sizes > 0
                        && size_of_optional_header >= 112 + 8
                    {
                        let dir_offset = opt_offset + 112;
                        let rva = u32::from_le_bytes(data[dir_offset..dir_offset + 4].try_into().unwrap());
                        let sz = u32::from_le_bytes(data[dir_offset + 4..dir_offset + 8].try_into().unwrap());
                        (rva, sz)
                    } else {
                        (0, 0)
                    };

                    (true, entry_point, img_base, img_size, hdr_size, sub_sys, exp_rva, exp_size)
                }
                magic::PE32 => {
                    // 32-bit PE32 Optional Header
                    const MIN_OPT32_SIZE: usize = 96;
                    if size_of_optional_header < MIN_OPT32_SIZE {
                        return Err(PeError::BufferTooSmall {
                            expected: MIN_OPT32_SIZE,
                            actual: size_of_optional_header,
                        });
                    }

                    let entry_point =
                        u32::from_le_bytes(data[opt_offset + 16..opt_offset + 20].try_into().unwrap());
                    let img_base =
                        u32::from_le_bytes(data[opt_offset + 28..opt_offset + 32].try_into().unwrap())
                            as u64;
                    let img_size =
                        u32::from_le_bytes(data[opt_offset + 56..opt_offset + 60].try_into().unwrap());
                    let hdr_size =
                        u32::from_le_bytes(data[opt_offset + 60..opt_offset + 64].try_into().unwrap());
                    let sub_sys =
                        u16::from_le_bytes(data[opt_offset + 68..opt_offset + 70].try_into().unwrap());
                    let num_rva_sizes =
                        u32::from_le_bytes(data[opt_offset + 92..opt_offset + 96].try_into().unwrap());

                    let (exp_rva, exp_size) = if num_rva_sizes > 0
                        && size_of_optional_header >= 96 + 8
                    {
                        let dir_offset = opt_offset + 96;
                        let rva = u32::from_le_bytes(data[dir_offset..dir_offset + 4].try_into().unwrap());
                        let sz = u32::from_le_bytes(data[dir_offset + 4..dir_offset + 8].try_into().unwrap());
                        (rva, sz)
                    } else {
                        (0, 0)
                    };

                    (false, entry_point, img_base, img_size, hdr_size, sub_sys, exp_rva, exp_size)
                }
                other => return Err(PeError::UnsupportedOptionalHeaderMagic(other)),
            };

        // 5. Parse Section Headers
        let section_table_offset = opt_offset + size_of_optional_header;
        const SECTION_HEADER_SIZE: usize = 40;
        let total_sections_bytes = (number_of_sections as usize).saturating_mul(SECTION_HEADER_SIZE);
        if section_table_offset.saturating_add(total_sections_bytes) > data.len() {
            return Err(PeError::TruncatedSectionHeaders);
        }

        let mut sections = Vec::with_capacity(number_of_sections as usize);
        for i in 0..number_of_sections as usize {
            let sec_off = section_table_offset + (i * SECTION_HEADER_SIZE);
            let raw_name = &data[sec_off..sec_off + 8];
            let name_len = raw_name.iter().position(|&b| b == 0).unwrap_or(8);
            let name = String::from_utf8_lossy(&raw_name[..name_len]).into_owned();

            let virtual_size =
                u32::from_le_bytes(data[sec_off + 8..sec_off + 12].try_into().unwrap());
            let virtual_address =
                u32::from_le_bytes(data[sec_off + 12..sec_off + 16].try_into().unwrap());
            let raw_data_size =
                u32::from_le_bytes(data[sec_off + 16..sec_off + 20].try_into().unwrap());
            let raw_data_offset =
                u32::from_le_bytes(data[sec_off + 20..sec_off + 24].try_into().unwrap());
            let sec_characteristics =
                u32::from_le_bytes(data[sec_off + 36..sec_off + 40].try_into().unwrap());

            sections.push(PeSection {
                name,
                virtual_address,
                virtual_size,
                raw_data_offset,
                raw_data_size,
                characteristics: sec_characteristics,
            });
        }

        // 6. Parse Export Directory (if present)
        let exports = if export_rva != 0 && export_size != 0 {
            Self::parse_export_directory(data, export_rva, export_size, &sections, size_of_headers)
        } else {
            None
        };

        Ok(PeInfo {
            is_64bit,
            machine,
            characteristics,
            subsystem,
            image_base,
            size_of_image,
            entry_point_rva,
            size_of_headers,
            sections,
            exports,
        })
    }

    /// Reads and parses a PE file from disk.
    ///
    /// # Arguments
    ///
    /// * `path` - The filesystem path to the target binary or DLL.
    ///
    /// # Returns
    ///
    /// The decoded [`PeInfo`] metadata.
    pub fn parse_file(path: impl AsRef<Path>) -> Result<PeInfo, PeError> {
        let bytes = std::fs::read(path.as_ref())
            .map_err(|e| PeError::IoError(format!("Failed to read file: {e}")))?;
        Self::parse(&bytes)
    }

    /// Translates a Relative Virtual Address (RVA) to a physical byte offset within the file buffer.
    pub fn rva_to_file_offset(
        rva: u32,
        sections: &[PeSection],
        size_of_headers: u32,
        file_len: usize,
    ) -> Option<usize> {
        // If RVA is within the header region before sections start
        if rva < size_of_headers && (rva as usize) < file_len {
            return Some(rva as usize);
        }

        // Find the section that encompasses this RVA
        for sec in sections {
            let virtual_span = sec.virtual_size.max(sec.raw_data_size);
            if rva >= sec.virtual_address && rva < sec.virtual_address.saturating_add(virtual_span) {
                let delta = rva - sec.virtual_address;
                if delta < sec.raw_data_size {
                    let offset = (sec.raw_data_offset as usize).saturating_add(delta as usize);
                    if offset < file_len {
                        return Some(offset);
                    }
                }
            }
        }

        None
    }

    /// Extracts a null-terminated ASCII string from the buffer at the given file offset.
    fn extract_ascii_string(data: &[u8], offset: usize) -> Option<String> {
        if offset >= data.len() {
            return None;
        }

        let slice = &data[offset..];
        let len = slice.iter().position(|&b| b == 0)?;
        Some(String::from_utf8_lossy(&slice[..len]).into_owned())
    }

    /// Parses the `IMAGE_EXPORT_DIRECTORY` table.
    fn parse_export_directory(
        data: &[u8],
        export_rva: u32,
        export_size: u32,
        sections: &[PeSection],
        size_of_headers: u32,
    ) -> Option<PeExportDirectory> {
        let export_off =
            Self::rva_to_file_offset(export_rva, sections, size_of_headers, data.len())?;
        const EXPORT_DIR_SIZE: usize = 40;
        if export_off.saturating_add(EXPORT_DIR_SIZE) > data.len() {
            return None;
        }

        let dir_data = &data[export_off..export_off + EXPORT_DIR_SIZE];
        let name_rva = u32::from_le_bytes(dir_data[12..16].try_into().unwrap());
        let ordinal_base = u32::from_le_bytes(dir_data[16..20].try_into().unwrap());
        let num_functions = u32::from_le_bytes(dir_data[20..24].try_into().unwrap());
        let num_names = u32::from_le_bytes(dir_data[24..28].try_into().unwrap());
        let addr_functions_rva = u32::from_le_bytes(dir_data[28..32].try_into().unwrap());
        let addr_names_rva = u32::from_le_bytes(dir_data[32..36].try_into().unwrap());
        let addr_ordinals_rva = u32::from_le_bytes(dir_data[36..40].try_into().unwrap());

        // Extract DLL name
        let dll_name = if name_rva != 0 {
            Self::rva_to_file_offset(name_rva, sections, size_of_headers, data.len())
                .and_then(|off| Self::extract_ascii_string(data, off))
        } else {
            None
        };

        // Extract function address array
        let func_table_off =
            Self::rva_to_file_offset(addr_functions_rva, sections, size_of_headers, data.len())?;
        let max_funcs = (num_functions as usize).min(65536);
        let mut function_rvas = Vec::with_capacity(max_funcs);

        for i in 0..max_funcs {
            let off = func_table_off + (i * 4);
            if off + 4 > data.len() {
                break;
            }
            let rva = u32::from_le_bytes(data[off..off + 4].try_into().unwrap());
            function_rvas.push(rva);
        }

        // Extract name and ordinal arrays
        let names_table_off =
            Self::rva_to_file_offset(addr_names_rva, sections, size_of_headers, data.len());
        let ordinals_table_off =
            Self::rva_to_file_offset(addr_ordinals_rva, sections, size_of_headers, data.len());

        let mut exports = Vec::new();
        let mut by_name = HashMap::new();
        let mut by_ordinal = HashMap::new();
        let export_end_rva = export_rva.saturating_add(export_size);

        if let (Some(names_off), Some(ord_off)) = (names_table_off, ordinals_table_off) {
            let max_names = (num_names as usize).min(65536);
            for i in 0..max_names {
                let name_ptr_off = names_off + (i * 4);
                let ord_ptr_off = ord_off + (i * 2);

                if name_ptr_off + 4 > data.len() || ord_ptr_off + 2 > data.len() {
                    break;
                }

                let str_rva = u32::from_le_bytes(data[name_ptr_off..name_ptr_off + 4].try_into().unwrap());
                let ord_idx = u16::from_le_bytes(data[ord_ptr_off..ord_ptr_off + 2].try_into().unwrap());

                let symbol_name = Self::rva_to_file_offset(str_rva, sections, size_of_headers, data.len())
                    .and_then(|off| Self::extract_ascii_string(data, off));

                if (ord_idx as usize) < function_rvas.len() {
                    let rva = function_rvas[ord_idx as usize];
                    let ordinal = (ordinal_base as u16).saturating_add(ord_idx);

                    // Check if RVA points to a forwarder string inside the export directory
                    let forwarder = if rva >= export_rva && rva < export_end_rva {
                        Self::rva_to_file_offset(rva, sections, size_of_headers, data.len())
                            .and_then(|off| Self::extract_ascii_string(data, off))
                    } else {
                        None
                    };

                    if let Some(ref name) = symbol_name {
                        by_name.insert(name.clone(), rva);
                    }
                    by_ordinal.insert(ordinal, rva);

                    exports.push(PeExport {
                        name: symbol_name,
                        ordinal,
                        rva,
                        forwarder,
                    });
                }
            }
        }

        // Add ordinal-only exports not mapped by name
        for (idx, &rva) in function_rvas.iter().enumerate() {
            let ordinal = (ordinal_base as u16).saturating_add(idx as u16);
            if rva != 0 && !by_ordinal.contains_key(&ordinal) {
                let forwarder = if rva >= export_rva && rva < export_end_rva {
                    Self::rva_to_file_offset(rva, sections, size_of_headers, data.len())
                        .and_then(|off| Self::extract_ascii_string(data, off))
                } else {
                    None
                };

                by_ordinal.insert(ordinal, rva);
                exports.push(PeExport {
                    name: None,
                    ordinal,
                    rva,
                    forwarder,
                });
            }
        }

        Some(PeExportDirectory {
            dll_name,
            export_table_rva: export_rva,
            export_table_size: export_size,
            ordinal_base,
            exports,
            by_name,
            by_ordinal,
        })
    }
}
