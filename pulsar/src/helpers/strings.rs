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

/// Parses a zero-copy null-terminated UTF-16LE slice (`&[u16]`) from bytes.
///
/// # Arguments
/// * `bytes` - The raw byte buffer starting from the UTF-16 string.
///
/// # Returns
/// A tuple of `(&[u16], usize)` containing the borrowed UTF-16 slice and total bytes consumed.
pub fn parse_utf16_slice(bytes: &[u8]) -> Result<(&[u16], usize), StringError> {
    let (aligned_bytes, padding) = if (bytes.as_ptr() as usize) % 2 != 0 {
        if bytes.is_empty() {
            return Ok((&[], 0));
        }
        (&bytes[1..], 1)
    } else {
        (bytes, 0)
    };

    let count = aligned_bytes.len() / 2;
    if count == 0 {
        return Ok((&[], padding));
    }

    let u16_slice = unsafe {
        std::slice::from_raw_parts(aligned_bytes.as_ptr() as *const u16, count)
    };

    let len = u16_slice.iter().position(|&c| c == 0).ok_or(StringError::MissingNullTerminator)?;
    let bytes_consumed = padding + ((len + 1) * 2).min(aligned_bytes.len());
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

    /// Validates pointer realignment and zero-copy UTF-16 decoding across both even and odd memory offsets.
    /// Critical for handling ETW ring buffers where dynamic-length preceding fields cause unaligned word boundaries.
    #[test]
    fn test_parse_utf16_slice_aligned_and_unaligned() {
        let aligned_data: [u16; 5] = [b'c' as u16, b'm' as u16, b'd' as u16, 0, 0x1234];
        let aligned_bytes = unsafe {
            std::slice::from_raw_parts(aligned_data.as_ptr() as *const u8, aligned_data.len() * 2)
        };
        let (slice, consumed) = parse_utf16_slice(aligned_bytes).expect("Aligned UTF-16 should parse");
        assert_eq!(slice, &[b'c' as u16, b'm' as u16, b'd' as u16]);
        assert_eq!(consumed, 8);

        // Dynamically align padding byte so the slice passed to parse_utf16_slice has an odd pointer address
        let mut raw_buf = vec![0x00u8; 32];
        let base_ptr = raw_buf.as_ptr() as usize;
        let odd_offset = if base_ptr % 2 == 0 { 1 } else { 0 };
        // The byte at odd_offset is the padding byte; the aligned u16 payload starts at odd_offset + 1 (even address)
        raw_buf[odd_offset + 1..odd_offset + 1 + aligned_bytes.len()].copy_from_slice(aligned_bytes);

        let odd_slice = &raw_buf[odd_offset..odd_offset + 1 + aligned_bytes.len()];
        let (slice_unaligned, consumed_unaligned) =
            parse_utf16_slice(odd_slice).expect("Unaligned UTF-16 should parse");
        assert_eq!(slice_unaligned, &[b'c' as u16, b'm' as u16, b'd' as u16]);
        assert_eq!(consumed_unaligned, 9);
    }

    /// Ensures unterminated UTF-16 byte streams return an error instead of slicing beyond allocated memory.
    /// Protects telemetry parser integrity when dealing with corrupted kernel stack or command line buffers.
    #[test]
    fn test_parse_utf16_slice_missing_null() {
        let unterminated: [u16; 3] = [b'a' as u16, b'b' as u16, b'c' as u16];
        let bytes = unsafe {
            std::slice::from_raw_parts(unterminated.as_ptr() as *const u8, unterminated.len() * 2)
        };
        let res = parse_utf16_slice(bytes);
        assert_eq!(res, Err(StringError::MissingNullTerminator));
    }

    /// Validates parser behavior when supplied with empty slices or single-byte padding remnants.
    /// Prevents slice construction panics on degenerate packets.
    #[test]
    fn test_parse_utf16_slice_empty() {
        assert_eq!(parse_utf16_slice(&[]), Ok((&[][..], 0)));
        assert_eq!(parse_utf16_slice(&[0x00]), Ok((&[][..], 0)));
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



