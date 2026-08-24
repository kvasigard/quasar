//! Unit tests for pure-Rust PE header parsing and export extraction.

use super::error::PeError;
use super::models::{file_flags, machine, magic, section_flags};
use super::parser::PeParser;

/// Helper generating a synthetic, valid 64-bit PE binary with an Export Directory in memory.
fn create_synthetic_pe64_with_exports() -> Vec<u8> {
    let mut buf = vec![0u8; 4096];

    // 1. DOS Header
    buf[0] = b'M';
    buf[1] = b'Z';
    let e_lfanew: u32 = 0x80;
    buf[0x3C..0x40].copy_from_slice(&e_lfanew.to_le_bytes());

    // 2. NT Signature ("PE\0\0")
    let nt_off = e_lfanew as usize;
    buf[nt_off..nt_off + 4].copy_from_slice(b"PE\0\0");

    // 3. COFF File Header (20 bytes)
    let coff_off = nt_off + 4;
    buf[coff_off..coff_off + 2].copy_from_slice(&machine::IMAGE_FILE_MACHINE_AMD64.to_le_bytes()); // Machine: AMD64
    buf[coff_off + 2..coff_off + 4].copy_from_slice(&2u16.to_le_bytes()); // NumberOfSections: 2 (.text, .edata)
    buf[coff_off + 16..coff_off + 18].copy_from_slice(&240u16.to_le_bytes()); // SizeOfOptionalHeader: 240
    let chars = file_flags::IMAGE_FILE_DLL | file_flags::IMAGE_FILE_EXECUTABLE_IMAGE;
    buf[coff_off + 18..coff_off + 20].copy_from_slice(&chars.to_le_bytes()); // Characteristics: DLL

    // 4. Optional Header 64-bit (starts at coff_off + 20 = nt_off + 24)
    let opt_off = coff_off + 20;
    buf[opt_off..opt_off + 2].copy_from_slice(&magic::PE32_PLUS.to_le_bytes()); // Magic: PE32+ (0x020B)
    buf[opt_off + 16..opt_off + 20].copy_from_slice(&0x1000u32.to_le_bytes()); // AddressOfEntryPoint: 0x1000
    buf[opt_off + 24..opt_off + 32].copy_from_slice(&0x0000_7FFF_1000_0000u64.to_le_bytes()); // ImageBase
    buf[opt_off + 56..opt_off + 60].copy_from_slice(&0x3000u32.to_le_bytes()); // SizeOfImage: 0x3000
    buf[opt_off + 60..opt_off + 64].copy_from_slice(&0x400u32.to_le_bytes()); // SizeOfHeaders: 0x400
    buf[opt_off + 68..opt_off + 70].copy_from_slice(&3u16.to_le_bytes()); // Subsystem: Console (3)
    buf[opt_off + 108..opt_off + 112].copy_from_slice(&16u32.to_le_bytes()); // NumberOfRvaAndSizes: 16

    // Data Directory 0 (Export Directory): RVA = 0x2000, Size = 0x1000
    let dir_export_off = opt_off + 112;
    buf[dir_export_off..dir_export_off + 4].copy_from_slice(&0x2000u32.to_le_bytes()); // Export RVA
    buf[dir_export_off + 4..dir_export_off + 8].copy_from_slice(&0x1000u32.to_le_bytes()); // Export Size

    // 5. Section Table (starts at opt_off + 240)
    let sec_table_off = opt_off + 240;

    // Section 1: ".text" (VirtualAddress: 0x1000, VirtualSize: 0x1000, RawOffset: 0x400, RawSize: 0x400)
    let sec1_off = sec_table_off;
    buf[sec1_off..sec1_off + 5].copy_from_slice(b".text");
    buf[sec1_off + 8..sec1_off + 12].copy_from_slice(&0x1000u32.to_le_bytes()); // VirtualSize
    buf[sec1_off + 12..sec1_off + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // VirtualAddress
    buf[sec1_off + 16..sec1_off + 20].copy_from_slice(&0x400u32.to_le_bytes()); // RawDataSize
    buf[sec1_off + 20..sec1_off + 24].copy_from_slice(&0x400u32.to_le_bytes()); // RawDataOffset
    buf[sec1_off + 36..sec1_off + 40]
        .copy_from_slice(&(section_flags::IMAGE_SCN_MEM_EXECUTE | section_flags::IMAGE_SCN_MEM_READ).to_le_bytes());

    // Section 2: ".edata" (VirtualAddress: 0x2000, VirtualSize: 0x1000, RawOffset: 0x800, RawSize: 0x800)
    let sec2_off = sec_table_off + 40;
    buf[sec2_off..sec2_off + 6].copy_from_slice(b".edata");
    buf[sec2_off + 8..sec2_off + 12].copy_from_slice(&0x1000u32.to_le_bytes()); // VirtualSize
    buf[sec2_off + 12..sec2_off + 16].copy_from_slice(&0x2000u32.to_le_bytes()); // VirtualAddress
    buf[sec2_off + 16..sec2_off + 20].copy_from_slice(&0x800u32.to_le_bytes()); // RawDataSize
    buf[sec2_off + 20..sec2_off + 24].copy_from_slice(&0x800u32.to_le_bytes()); // RawDataOffset (0x800)
    buf[sec2_off + 36..sec2_off + 40]
        .copy_from_slice(&(section_flags::IMAGE_SCN_MEM_READ).to_le_bytes());

    // 6. Populate .edata at RawOffset = 0x800 (RVA = 0x2000)
    // Export Directory Struct (40 bytes)
    let edata_raw = 0x800usize;
    let dll_name_rva = 0x2050u32; // DLL Name string RVA
    let ordinal_base = 1u32;
    let num_functions = 2u32;
    let num_names = 2u32;
    let addr_functions_rva = 0x2060u32;
    let addr_names_rva = 0x2070u32;
    let addr_ordinals_rva = 0x2080u32;

    buf[edata_raw + 12..edata_raw + 16].copy_from_slice(&dll_name_rva.to_le_bytes());
    buf[edata_raw + 16..edata_raw + 20].copy_from_slice(&ordinal_base.to_le_bytes());
    buf[edata_raw + 20..edata_raw + 24].copy_from_slice(&num_functions.to_le_bytes());
    buf[edata_raw + 24..edata_raw + 28].copy_from_slice(&num_names.to_le_bytes());
    buf[edata_raw + 28..edata_raw + 32].copy_from_slice(&addr_functions_rva.to_le_bytes());
    buf[edata_raw + 32..edata_raw + 36].copy_from_slice(&addr_names_rva.to_le_bytes());
    buf[edata_raw + 36..edata_raw + 40].copy_from_slice(&addr_ordinals_rva.to_le_bytes());

    // DLL Name string at raw offset 0x850 (RVA 0x2050): "testdll.dll\0"
    let dll_name_raw = 0x850usize;
    buf[dll_name_raw..dll_name_raw + 12].copy_from_slice(b"testdll.dll\0");

    // AddressOfFunctions array (2 functions) at raw offset 0x860 (RVA 0x2060)
    // Func 0: RVA 0x1020 (in .text)
    // Func 1: RVA 0x1050 (in .text)
    let funcs_raw = 0x860usize;
    buf[funcs_raw..funcs_raw + 4].copy_from_slice(&0x1020u32.to_le_bytes());
    buf[funcs_raw + 4..funcs_raw + 8].copy_from_slice(&0x1050u32.to_le_bytes());

    // AddressOfNames array (2 names) at raw offset 0x870 (RVA 0x2070)
    // Name 0: RVA 0x2090 ("NtAllocateVirtualMemory\0")
    // Name 1: RVA 0x20B0 ("NtProtectVirtualMemory\0")
    let names_raw = 0x870usize;
    buf[names_raw..names_raw + 4].copy_from_slice(&0x2090u32.to_le_bytes());
    buf[names_raw + 4..names_raw + 8].copy_from_slice(&0x20B0u32.to_le_bytes());

    // AddressOfNameOrdinals array (2 ordinals: 0, 1) at raw offset 0x880 (RVA 0x2080)
    let ords_raw = 0x880usize;
    buf[ords_raw..ords_raw + 2].copy_from_slice(&0u16.to_le_bytes());
    buf[ords_raw + 2..ords_raw + 4].copy_from_slice(&1u16.to_le_bytes());

    // Name strings:
    // Name 0: "NtAllocateVirtualMemory\0" at raw offset 0x890 (RVA 0x2090)
    let name0_raw = 0x890usize;
    buf[name0_raw..name0_raw + 24].copy_from_slice(b"NtAllocateVirtualMemory\0");

    // Name 1: "NtProtectVirtualMemory\0" at raw offset 0x8B0 (RVA 0x20B0)
    let name1_raw = 0x8B0usize;
    buf[name1_raw..name1_raw + 23].copy_from_slice(b"NtProtectVirtualMemory\0");

    buf
}

#[test]
fn test_parse_synthetic_64bit_pe_exports() {
    let bytes = create_synthetic_pe64_with_exports();
    let pe = PeParser::parse(&bytes).expect("Failed to parse synthetic PE64");

    assert!(pe.is_64bit);
    assert!(pe.is_dll());
    assert_eq!(pe.machine, machine::IMAGE_FILE_MACHINE_AMD64);
    assert_eq!(pe.image_base, 0x0000_7FFF_1000_0000);
    assert_eq!(pe.entry_point_rva, 0x1000);
    assert_eq!(pe.sections.len(), 2);
    assert_eq!(pe.sections[0].name, ".text");
    assert!(pe.sections[0].is_executable());
    assert_eq!(pe.sections[1].name, ".edata");
    assert!(!pe.sections[1].is_executable());

    let exports = pe.exports.as_ref().expect("Export directory must be present");
    assert_eq!(exports.dll_name.as_deref(), Some("testdll.dll"));
    assert_eq!(exports.exports.len(), 2);

    // Verify fast name lookup
    let rva_alloc = exports.find_rva_by_name("NtAllocateVirtualMemory");
    assert_eq!(rva_alloc, Some(0x1020));

    let rva_protect = exports.find_rva_by_name("NtProtectVirtualMemory");
    assert_eq!(rva_protect, Some(0x1050));

    // Verify ordinal lookup (bias = 1)
    let rva_ord1 = exports.find_rva_by_ordinal(1);
    assert_eq!(rva_ord1, Some(0x1020));
    let rva_ord2 = exports.find_rva_by_ordinal(2);
    assert_eq!(rva_ord2, Some(0x1050));

    // Verify RVA export lookup
    let exp_record = pe.find_export_by_rva(0x1020).expect("Must find export by RVA");
    assert_eq!(exp_record.name.as_deref(), Some("NtAllocateVirtualMemory"));
    assert_eq!(exp_record.ordinal, 1);
}

#[test]
fn test_parse_corrupted_pe_rejection() {
    // 1. Empty buffer
    assert_eq!(
        PeParser::parse(&[]),
        Err(PeError::BufferTooSmall {
            expected: 64,
            actual: 0
        })
    );

    // 2. Invalid DOS magic
    let mut invalid_dos = vec![0u8; 128];
    invalid_dos[0] = b'X';
    invalid_dos[1] = b'Y';
    assert_eq!(PeParser::parse(&invalid_dos), Err(PeError::InvalidDosSignature));

    // 3. Out-of-bounds e_lfanew
    let mut bad_lfanew = vec![0u8; 128];
    bad_lfanew[0] = b'M';
    bad_lfanew[1] = b'Z';
    bad_lfanew[0x3C..0x40].copy_from_slice(&0xFFFF_0000u32.to_le_bytes());
    assert!(matches!(
        PeParser::parse(&bad_lfanew),
        Err(PeError::InvalidPeHeaderOffset(_))
    ));

    // 4. Invalid NT signature
    let mut bad_nt = vec![0u8; 256];
    bad_nt[0] = b'M';
    bad_nt[1] = b'Z';
    bad_nt[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    bad_nt[0x80..0x84].copy_from_slice(b"NOPE");
    assert_eq!(PeParser::parse(&bad_nt), Err(PeError::InvalidPeSignature));
}

#[test]
#[cfg(target_os = "windows")]
fn test_parse_real_system_dlls() {
    let ntdll_path = r"C:\Windows\System32\ntdll.dll";
    if std::path::Path::new(ntdll_path).exists() {
        let pe = PeParser::parse_file(ntdll_path).expect("Failed to parse live ntdll.dll");
        assert!(pe.is_dll());
        assert!(pe.is_64bit);
        assert!(!pe.sections.is_empty());

        let exports = pe.exports.expect("ntdll.dll must have an export directory");
        assert!(exports.exports.len() > 100);

        // ntdll must export standard system call stubs
        let rva_alloc = exports.find_rva_by_name("NtAllocateVirtualMemory");
        assert!(rva_alloc.is_some(), "NtAllocateVirtualMemory must be exported");

        let rva_protect = exports.find_rva_by_name("NtProtectVirtualMemory");
        assert!(rva_protect.is_some(), "NtProtectVirtualMemory must be exported");

        let rva_write = exports.find_rva_by_name("NtWriteVirtualMemory");
        assert!(rva_write.is_some(), "NtWriteVirtualMemory must be exported");
    }
}
