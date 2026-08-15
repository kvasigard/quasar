//! String decoding utilities for Windows ETW telemetry payloads.

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
