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

