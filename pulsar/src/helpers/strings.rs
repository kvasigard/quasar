//! String decoding utilities for Windows ETW telemetry payloads.

use std::str;
use thiserror::Error;

/// Error type when parsing strings from raw ETW byte slices.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum StringError {
    #[error("Missing null terminator")]
    MissingNullTerminator,

    #[error("Invalid UTF-8 encoding")]
    InvalidEncoding,
}

/// Parses a zero-copy null-terminated ANSI (or UTF-8) string slice from bytes.
///
/// # Arguments
/// * `bytes` - The raw byte buffer starting from the string.
///
/// # Returns
/// A tuple of `(&str, usize)` containing the borrowed string slice and total bytes consumed (including null terminator).
pub fn parse_ansi_string(bytes: &[u8]) -> Result<(&str, usize), StringError> {
    let null_pos = bytes.iter().position(|&b| b == 0).ok_or(StringError::MissingNullTerminator)?;
    let s = str::from_utf8(&bytes[..null_pos]).map_err(|_| StringError::InvalidEncoding)?;
    Ok((s, null_pos + 1))
}

/// Parses a zero-copy null-terminated UTF-16LE byte slice (`&[u8]`) without requiring 2-byte pointer alignment.
///
/// Packed ETW structures (such as `Process_V2_TypeGroup1`) place `CommandLine` immediately after the
/// null-terminated ANSI `ImageFileName` with zero alignment padding. Scanning `chunks_exact(2)` for `[0, 0]`
/// avoids unaligned `&[u16]` slice Undefined Behavior and never drops the first byte on odd memory addresses.
///
/// # Arguments
/// * `bytes` - The raw byte buffer starting at the UTF-16LE string.
///
/// # Returns
/// A tuple of `(&[u8], usize)` containing the UTF-16LE code unit bytes (excluding the `[0, 0]` terminator)
/// and total bytes consumed (including the 2-byte null terminator).
pub fn parse_utf16_bytes(bytes: &[u8]) -> Result<(&[u8], usize), StringError> {
    if bytes.is_empty() {
        return Ok((&[], 0));
    }

    let char_count = bytes
        .chunks_exact(2)
        .position(|pair| pair[0] == 0 && pair[1] == 0)
        .ok_or(StringError::MissingNullTerminator)?;

    let byte_len = char_count * 2;
    let consumed = byte_len + 2;
    Ok((&bytes[..byte_len], consumed))
}

/// Decodes a raw UTF-16LE byte slice (`&[u8]`) into an owned `String` safely regardless of memory alignment.
///
/// # Arguments
/// * `bytes` - Raw UTF-16LE byte slice (2 bytes per code unit).
///
/// # Returns
/// Decoded UTF-8 `String` (replacing any unpaired surrogates with the replacement character).
pub fn decode_utf16le_bytes(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect();
    String::from_utf16_lossy(&units)
}

/// Parses a zero-copy null-terminated UTF-16LE slice (`&[u16]`) from 2-byte aligned bytes.
///
/// Returns `Err(StringError::InvalidEncoding)` if `bytes` is not 2-byte aligned in memory;
/// callers parsing packed unaligned ETW fields should use [`parse_utf16_bytes`] and [`decode_utf16le_bytes`].
///
/// # Arguments
/// * `bytes` - The 2-byte aligned raw byte buffer starting at the UTF-16 string.
///
/// # Returns
/// A tuple of `(&[u16], usize)` containing the borrowed UTF-16 slice and total bytes consumed.
pub fn parse_utf16_slice(bytes: &[u8]) -> Result<(&[u16], usize), StringError> {
    if bytes.len() < 2 {
        return Ok((&[], 0));
    }

    if !(bytes.as_ptr() as usize).is_multiple_of(2) {
        return Err(StringError::InvalidEncoding);
    }

    let count = bytes.len() / 2;
    // SAFETY: `bytes` pointer was verified to be 2-byte aligned above and `count * 2 <= bytes.len()`.
    let u16_slice = unsafe { std::slice::from_raw_parts(bytes.as_ptr() as *const u16, count) };

    let len = u16_slice
        .iter()
        .position(|&c| c == 0)
        .ok_or(StringError::MissingNullTerminator)?;
    let bytes_consumed = (len + 1) * 2;
    Ok((&u16_slice[..len], bytes_consumed))
}

/// Decodes a null-terminated UTF-16LE string from an ETW byte slice starting at a given offset.
///
/// # Arguments
///
/// * `bytes` - The raw byte buffer containing the UTF-16LE character stream.
/// * `offset` - The byte offset within `bytes` where the string begins.
///
/// # Returns
///
/// A tuple containing:
/// * `Option<String>` - The decoded `String` if UTF-16 decoding succeeded, or `None`.
/// * `usize` - The new byte offset immediately following the null terminator.
pub fn extract_utf16_string(bytes: &[u8], offset: usize) -> (Option<String>, usize) {
    if offset >= bytes.len() {
        return (None, offset);
    }

    let slice = &bytes[offset..];
    let u16_pairs: Vec<u16> = slice
        .chunks_exact(2)
        .map(|chunk| u16::from_ne_bytes([chunk[0], chunk[1]]))
        .take_while(|&code_unit| code_unit != 0)
        .collect();

    let bytes_consumed = (u16_pairs.len() + 1) * 2;
    let string_result = String::from_utf16(&u16_pairs).ok();

    (string_result, offset + bytes_consumed)
}

/// Decodes a null-terminated ANSI (or UTF-8 lossy) string from a raw byte slice.
///
/// # Arguments
///
/// * `bytes` - The raw byte slice containing ASCII/ANSI characters.
///
/// # Returns
///
/// A trimmed `String` up to the first null byte.
pub fn extract_ansi_string(bytes: &[u8]) -> String {
    let null_pos = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..null_pos])
        .trim()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verifies zero-copy extraction and byte count accounting for well-formed null-terminated ANSI strings.
    /// Prevents string truncation and index misalignment when progressing to subsequent packet fields.
    #[test]
    fn test_parse_ansi_string_valid() {
        let buffer = b"svchost.exe\0trailing_garbage";
        let (s, consumed) = parse_ansi_string(buffer).expect("Should parse ANSI string");
        assert_eq!(s, "svchost.exe");
        assert_eq!(consumed, 12);
    }

    /// Ensures unterminated byte buffers return MissingNullTerminator rather than reading past buffer boundaries.
    /// Essential for defending against malformed or malicious ETW payloads that could trigger out-of-bounds reads.
    #[test]
    fn test_parse_ansi_string_missing_null() {
        let buffer = b"unterminated_process_name";
        let res = parse_ansi_string(buffer);
        assert_eq!(res, Err(StringError::MissingNullTerminator));
    }

    /// Asserts that non-UTF-8 byte sequences are detected and flagged with InvalidEncoding.
    /// Prevents invalid Unicode slices from propagating into downstream detection logic and causing panics.
    #[test]
    fn test_parse_ansi_string_invalid_utf8() {
        let buffer = &[0xFF, 0xFE, 0xFD, 0x00];
        let res = parse_ansi_string(buffer);
        assert_eq!(res, Err(StringError::InvalidEncoding));
    }

    /// Validates alignment-agnostic UTF-16LE byte parsing across both even and odd memory offsets
    /// without corrupting or dropping the first byte of the UTF-16LE string (`PUL-02`).
    #[test]
    fn test_parse_utf16_bytes_even_and_odd_alignment() {
        let aligned_data: [u16; 5] = [b'c' as u16, b'm' as u16, b'd' as u16, 0, 0x1234];
        let aligned_bytes = unsafe {
            std::slice::from_raw_parts(aligned_data.as_ptr() as *const u8, aligned_data.len() * 2)
        };
        let (slice, consumed) =
            parse_utf16_slice(aligned_bytes).expect("Aligned UTF-16 should parse");
        assert_eq!(slice, &[b'c' as u16, b'm' as u16, b'd' as u16]);
        assert_eq!(consumed, 8);

        // Place UTF-16LE payload at an explicitly odd memory address and verify no byte is skipped
        let mut raw_buf = [0x00u8; 32];
        let base_ptr = raw_buf.as_ptr() as usize;
        let odd_offset = if base_ptr.is_multiple_of(2) { 1 } else { 0 };
        raw_buf[odd_offset..odd_offset + aligned_bytes.len()].copy_from_slice(aligned_bytes);

        let odd_slice = &raw_buf[odd_offset..odd_offset + aligned_bytes.len()];
        let (utf16_bytes, consumed_unaligned) =
            parse_utf16_bytes(odd_slice).expect("Unaligned UTF-16LE bytes must parse cleanly");
        assert_eq!(decode_utf16le_bytes(utf16_bytes), "cmd");
        assert_eq!(consumed_unaligned, 8);
    }

    /// Ensures unterminated UTF-16 byte streams return an error instead of slicing beyond allocated memory.
    /// Protects telemetry parser integrity when dealing with corrupted kernel stack or command line buffers.
    #[test]
    fn test_parse_utf16_slice_missing_null() {
        let unterminated: [u16; 3] = [b'a' as u16, b'b' as u16, b'c' as u16];
        let bytes = unsafe {
            std::slice::from_raw_parts(unterminated.as_ptr() as *const u8, unterminated.len() * 2)
        };
        assert_eq!(parse_utf16_slice(bytes), Err(StringError::MissingNullTerminator));
        assert_eq!(parse_utf16_bytes(bytes), Err(StringError::MissingNullTerminator));
    }

    /// Validates parser behavior when supplied with empty slices or single-byte padding remnants.
    /// Prevents slice construction panics on degenerate packets.
    #[test]
    fn test_parse_utf16_slice_empty() {
        assert_eq!(parse_utf16_slice(&[]), Ok((&[][..], 0)));
        assert_eq!(parse_utf16_slice(&[0x00]), Ok((&[][..], 0)));
        assert_eq!(parse_utf16_bytes(&[]), Ok((&[][..], 0)));
    }

    /// Verifies UTF-16 string conversion and bounds checking when offsets exceed or match buffer length.
    /// Prevents index out-of-range panics when parsing truncated process command line payloads.
    #[test]
    fn test_extract_utf16_string_bounds() {
        let mut wide: Vec<u8> = "notepad.exe\0".encode_utf16().flat_map(|c| c.to_ne_bytes()).collect();
        wide.extend_from_slice(&[0x99, 0x99]);

        let (extracted, next_offset) = extract_utf16_string(&wide, 0);
        assert_eq!(extracted, Some("notepad.exe".to_string()));
        assert_eq!(next_offset, 24);

        let (out_of_bounds, ret_offset) = extract_utf16_string(&wide, 100);
        assert_eq!(out_of_bounds, None);
        assert_eq!(ret_offset, 100);
    }
}



