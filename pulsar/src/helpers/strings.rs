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

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests extraction of a standard null-terminated UTF-16LE string.
    #[test]
    fn test_extract_utf16_standard() {
        // "cmd.exe\0" in UTF-16LE
        let raw: Vec<u8> = vec![
            b'c', 0, b'm', 0, b'd', 0, b'.', 0, b'e', 0, b'x', 0, b'e', 0, 0, 0,
        ];
        let (decoded, next_offset) = extract_utf16_string(&raw, 0);
        assert_eq!(decoded, Some("cmd.exe".to_string()));
        assert_eq!(next_offset, 16);
    }

    /// Tests consecutive UTF-16LE string extraction with an initial offset.
    #[test]
    fn test_extract_utf16_chained_offset() {
        // Padding (4 bytes) + "svchost\0" + "powershell\0"
        let mut raw = vec![0xAA, 0xBB, 0xCC, 0xDD];
        let str1: Vec<u16> = "svchost\0".encode_utf16().collect();
        for u in str1 {
            raw.extend_from_slice(&u.to_ne_bytes());
        }
        let str2: Vec<u16> = "powershell\0".encode_utf16().collect();
        for u in str2 {
            raw.extend_from_slice(&u.to_ne_bytes());
        }

        let (first, offset2) = extract_utf16_string(&raw, 4);
        assert_eq!(first, Some("svchost".to_string()));

        let (second, offset3) = extract_utf16_string(&raw, offset2);
        assert_eq!(second, Some("powershell".to_string()));
        assert_eq!(offset3, raw.len());
    }

    /// Tests edge case where offset is out of bounds or slice is empty.
    #[test]
    fn test_extract_utf16_out_of_bounds() {
        let raw = vec![b'a', 0];
        let (res, offset) = extract_utf16_string(&raw, 10);
        assert_eq!(res, None);
        assert_eq!(offset, 10);
    }

    /// Tests extraction of standard null-terminated ANSI strings.
    #[test]
    fn test_extract_ansi_standard() {
        let raw = b"svchost.exe\0extra_padding_bytes";
        let res = extract_ansi_string(raw);
        assert_eq!(res, "svchost.exe");
    }

    /// Tests ANSI extraction with no null terminator (takes full length trimmed).
    #[test]
    fn test_extract_ansi_no_null() {
        let raw = b"  powershell.exe  ";
        let res = extract_ansi_string(raw);
        assert_eq!(res, "powershell.exe");
    }
}
