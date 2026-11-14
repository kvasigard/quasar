//! Zero-cost, bitness-aware binary cursor for decoding packed Windows ETW payloads.
//!
//! [`ByteCursor`] eliminates manual byte-offset arithmetic and hardcoded host pointer sizes
//! (`std::mem::size_of::<usize>()`) when parsing ETW MOF and manifest schemas. By carrying the
//! event's actual pointer byte width (`4` bytes for 32-bit WOW64 events vs. `8` bytes for 64-bit
//! events, derived from `EVENT_HEADER_FLAG_32_BIT_HEADER`), sequential field reads automatically
//! advance by the exact number of bytes required.

use thiserror::Error;

use crate::helpers::strings::{
    StringError, decode_utf16le_bytes, parse_ansi_string, parse_utf16_bytes,
};
use crate::sensors::etw::RawEvent;

/// Fallback binary `S-1-0-0` (Null SID) returned when a kernel ETW record carries a `0u32`
/// null-SID marker (e.g., `Idle` pseudo-process during `DCStart`).
pub const NULL_SID_BYTES: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

/// Errors encountered while reading structured fields from an ETW payload via [`ByteCursor`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum CursorError {
    /// The remaining slice does not contain enough bytes for the requested field.
    #[error("Buffer too short for field '{field}' (needed {needed} bytes, remaining {remaining})")]
    BufferTooShort {
        field: &'static str,
        needed: usize,
        remaining: usize,
    },

    /// A binary Windows SID structure had an invalid revision or truncated sub-authority array.
    #[error("Invalid binary SID in field '{0}'")]
    InvalidSid(&'static str),

    /// A null-terminated ANSI or UTF-16LE string failed to parse.
    #[error("String parsing error in field '{0}': {1}")]
    String(&'static str, #[source] StringError),

    /// Trailing payload bytes are not a multiple of the expected element size.
    #[error("Unaligned trailing array in field '{field}': {remaining} bytes remaining")]
    UnalignedTrailingBytes {
        field: &'static str,
        remaining: usize,
    },
}

/// Zero-copy sequential binary reader parameterized by the event's pointer byte width (`4` or `8`).
#[derive(Debug, Clone, Copy)]
pub struct ByteCursor<'a> {
    data: &'a [u8],
    pos: usize,
    ptr_size: usize,
}

impl<'a> ByteCursor<'a> {
    /// Creates a new [`ByteCursor`] over `data` using the host architecture's pointer width.
    #[inline(always)]
    pub const fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            pos: 0,
            ptr_size: std::mem::size_of::<usize>(),
        }
    }

    /// Creates a new [`ByteCursor`] over `data` with an explicit pointer width (`4` or `8` bytes).
    #[inline(always)]
    pub const fn with_pointer_size(data: &'a [u8], ptr_size: usize) -> Self {
        let normalized_ptr_size = if ptr_size == 4 { 4 } else { 8 };
        Self {
            data,
            pos: 0,
            ptr_size: normalized_ptr_size,
        }
    }

    /// Creates a new [`ByteCursor`] directly from a borrowed [`RawEvent`], automatically
    /// inheriting its payload slice and 32/64-bit pointer width.
    #[inline(always)]
    pub fn from_raw_event(event: &'a RawEvent) -> Self {
        Self::with_pointer_size(event.user_data(), event.pointer_size())
    }

    /// Returns the current byte offset from the start of the buffer.
    #[inline(always)]
    pub const fn position(&self) -> usize {
        self.pos
    }

    /// Returns the number of unread bytes remaining in the buffer.
    #[inline(always)]
    pub const fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    /// Returns `true` if no unread bytes remain.
    #[inline(always)]
    pub const fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    /// Returns the pointer byte width (`4` or `8`) configured for this cursor.
    #[inline(always)]
    pub const fn pointer_size(&self) -> usize {
        self.ptr_size
    }

    /// Returns the unread tail of the underlying byte slice without advancing the cursor.
    #[inline(always)]
    pub fn remaining_slice(&self) -> &'a [u8] {
        &self.data[self.pos..]
    }

    /// Verifies that at least `needed` bytes remain in the buffer.
    #[inline(always)]
    pub fn ensure_remaining(&self, needed: usize, field: &'static str) -> Result<(), CursorError> {
        let rem = self.remaining();
        if rem < needed {
            Err(CursorError::BufferTooShort {
                field,
                needed,
                remaining: rem,
            })
        } else {
            Ok(())
        }
    }

    /// Reads exactly `len` bytes as a zero-copy subslice and advances the cursor.
    #[inline(always)]
    pub fn read_bytes(&mut self, len: usize, field: &'static str) -> Result<&'a [u8], CursorError> {
        self.ensure_remaining(len, field)?;
        let slice = &self.data[self.pos..self.pos + len];
        self.pos += len;
        Ok(slice)
    }

    /// Advances the cursor by `len` bytes without returning the skipped slice.
    #[inline(always)]
    pub fn skip(&mut self, len: usize, field: &'static str) -> Result<(), CursorError> {
        self.ensure_remaining(len, field)?;
        self.pos += len;
        Ok(())
    }

    /// Reads an unsigned 8-bit integer (`u8`).
    #[inline(always)]
    pub fn read_u8(&mut self, field: &'static str) -> Result<u8, CursorError> {
        let bytes = self.read_bytes(1, field)?;
        Ok(bytes[0])
    }

    /// Reads a native-endian unsigned 16-bit integer (`u16`).
    #[inline(always)]
    pub fn read_u16(&mut self, field: &'static str) -> Result<u16, CursorError> {
        let bytes = self.read_bytes(2, field)?;
        Ok(u16::from_ne_bytes([bytes[0], bytes[1]]))
    }

    /// Reads a native-endian unsigned 32-bit integer (`u32`).
    #[inline(always)]
    pub fn read_u32(&mut self, field: &'static str) -> Result<u32, CursorError> {
        let bytes = self.read_bytes(4, field)?;
        Ok(u32::from_ne_bytes(bytes.try_into().unwrap()))
    }

    /// Reads a native-endian signed 32-bit integer (`i32`).
    #[inline(always)]
    pub fn read_i32(&mut self, field: &'static str) -> Result<i32, CursorError> {
        let bytes = self.read_bytes(4, field)?;
        Ok(i32::from_ne_bytes(bytes.try_into().unwrap()))
    }

    /// Reads a native-endian unsigned 64-bit integer (`u64`).
    #[inline(always)]
    pub fn read_u64(&mut self, field: &'static str) -> Result<u64, CursorError> {
        let bytes = self.read_bytes(8, field)?;
        Ok(u64::from_ne_bytes(bytes.try_into().unwrap()))
    }

    /// Reads a native-endian signed 64-bit integer (`i64`).
    #[inline(always)]
    pub fn read_i64(&mut self, field: &'static str) -> Result<i64, CursorError> {
        let bytes = self.read_bytes(8, field)?;
        Ok(i64::from_ne_bytes(bytes.try_into().unwrap()))
    }

    /// Reads a native-endian unsigned 128-bit integer (`u128`).
    #[inline(always)]
    pub fn read_u128(&mut self, field: &'static str) -> Result<u128, CursorError> {
        let bytes = self.read_bytes(16, field)?;
        Ok(u128::from_ne_bytes(bytes.try_into().unwrap()))
    }

    /// Reads a pointer-sized integer (`4` or `8` bytes depending on `self.pointer_size()`)
    /// and zero-extends it to `u64`.
    #[inline(always)]
    pub fn read_ptr_u64(&mut self, field: &'static str) -> Result<u64, CursorError> {
        if self.ptr_size == 4 {
            Ok(self.read_u32(field)? as u64)
        } else {
            self.read_u64(field)
        }
    }

    /// Reads a pointer-sized integer (`4` or `8` bytes depending on `self.pointer_size()`)
    /// as a host `usize`.
    #[inline(always)]
    pub fn read_ptr_usize(&mut self, field: &'static str) -> Result<usize, CursorError> {
        Ok(self.read_ptr_u64(field)? as usize)
    }

    /// Reads a Windows binary Security Identifier (`SID`) from the current cursor position,
    /// handling both raw `SID` structures and kernel ETW `[extension("Sid")]` payloads prefixed
    /// by a `TOKEN_USER` (`2 * pointer_size` bytes) header or a `0u32` null-SID marker.
    #[inline]
    pub fn read_sid(&mut self, field: &'static str) -> Result<&'a [u8], CursorError> {
        let rem = self.remaining_slice();
        if rem.len() < 4 {
            return Err(CursorError::BufferTooShort {
                field,
                needed: 4,
                remaining: rem.len(),
            });
        }

        // In Windows ETW MOF `[extension("Sid")]`, a leading 32-bit 0 indicates no SID is attached
        // (unless it is the low 32 bits of a 64-bit canonical kernel pointer `0xFFFF...`).
        let is_64bit_kernel_ptr =
            self.ptr_size == 8 && rem.len() >= 8 && rem[6] == 0xFF && rem[7] == 0xFF;
        if rem[0..4] == [0, 0, 0, 0] && !is_64bit_kernel_ptr {
            self.pos += 4;
            return Ok(&NULL_SID_BYTES);
        }

        if rem.len() < 8 {
            return Err(CursorError::BufferTooShort {
                field,
                needed: 8,
                remaining: rem.len(),
            });
        }

        // Distinguish a direct raw SID (Revision == 1, SubAuthorityCount 1..=15, upper 4 bytes of
        // big-endian IdentifierAuthority == 0) from a kernel ETW `TOKEN_USER` (`2 * ptr_size` bytes)
        // header preceding the SID.
        let is_raw_sid = rem[0] == 1 && (1..=15).contains(&rem[1]) && rem[2..6] == [0, 0, 0, 0];
        let sid_offset = if is_raw_sid { 0 } else { 2 * self.ptr_size };

        if rem.len() < sid_offset + 8 {
            return Err(CursorError::BufferTooShort {
                field,
                needed: sid_offset + 8,
                remaining: rem.len(),
            });
        }

        if rem[sid_offset] != 1 {
            return Err(CursorError::InvalidSid(field));
        }

        let sub_auth_count = rem[sid_offset + 1] as usize;
        let sid_len = 8 + (sub_auth_count * 4);
        let total_consumed = sid_offset + sid_len;

        if rem.len() < total_consumed {
            return Err(CursorError::InvalidSid(field));
        }

        self.pos += total_consumed;
        Ok(&rem[sid_offset..total_consumed])
    }

    /// Reads a zero-copy null-terminated ANSI/UTF-8 string slice and advances past the NUL byte.
    #[inline]
    pub fn read_ansi_str(&mut self, field: &'static str) -> Result<&'a str, CursorError> {
        let (s, consumed) = parse_ansi_string(self.remaining_slice())
            .map_err(|e| CursorError::String(field, e))?;
        self.pos += consumed;
        Ok(s)
    }

    /// Reads a zero-copy null-terminated UTF-16LE byte slice (excluding the 2-byte `[0, 0]` terminator)
    /// without requiring 2-byte memory alignment, and advances the cursor past the terminator.
    #[inline]
    pub fn read_utf16_bytes(&mut self, field: &'static str) -> Result<&'a [u8], CursorError> {
        let (bytes, consumed) = parse_utf16_bytes(self.remaining_slice())
            .map_err(|e| CursorError::String(field, e))?;
        self.pos += consumed;
        Ok(bytes)
    }

    /// Reads a null-terminated UTF-16LE string and decodes it into an owned `String` safely regardless of alignment.
    #[inline]
    pub fn read_utf16_string(&mut self, field: &'static str) -> Result<String, CursorError> {
        let raw_bytes = self.read_utf16_bytes(field)?;
        Ok(decode_utf16le_bytes(raw_bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_byte_cursor_primitives_and_bitness_aware_pointers() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&0x1122_3344u32.to_ne_bytes()); // 4-byte ptr in 32-bit mode
        buf.extend_from_slice(&42u16.to_ne_bytes());
        buf.extend_from_slice(&99u8.to_ne_bytes());

        let mut cur32 = ByteCursor::with_pointer_size(&buf, 4);
        assert_eq!(cur32.pointer_size(), 4);
        assert_eq!(cur32.read_ptr_u64("Ptr32").unwrap(), 0x1122_3344);
        assert_eq!(cur32.read_u16("Val16").unwrap(), 42);
        assert_eq!(cur32.read_u8("Val8").unwrap(), 99);
        assert!(cur32.is_empty());

        let mut buf64 = Vec::new();
        buf64.extend_from_slice(&0xFFFF_8000_1122_3344u64.to_ne_bytes());
        let mut cur64 = ByteCursor::with_pointer_size(&buf64, 8);
        assert_eq!(cur64.read_ptr_u64("Ptr64").unwrap(), 0xFFFF_8000_1122_3344);
        assert!(cur64.is_empty());
    }

    #[test]
    fn test_byte_cursor_sid_with_32bit_and_64bit_token_user_header() {
        let raw_sid = [1u8, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0]; // S-1-5-18

        // 1. 32-bit TOKEN_USER header (2 * 4 = 8 bytes) before SID
        let mut buf32 = Vec::new();
        buf32.extend_from_slice(&0x8000_1234u32.to_ne_bytes()); // Sid ptr
        buf32.extend_from_slice(&0u32.to_ne_bytes()); // Attributes
        buf32.extend_from_slice(&raw_sid);

        let mut cur32 = ByteCursor::with_pointer_size(&buf32, 4);
        let parsed32 = cur32.read_sid("UserSID").unwrap();
        assert_eq!(parsed32, &raw_sid);
        assert!(cur32.is_empty());

        // 2. 64-bit TOKEN_USER header (2 * 8 = 16 bytes) before SID
        let mut buf64 = Vec::new();
        buf64.extend_from_slice(&0xFFFF_8000_0000_0000u64.to_ne_bytes()); // Canonical kernel ptr with low 32 bits == 0!
        buf64.extend_from_slice(&0u64.to_ne_bytes()); // Attributes
        buf64.extend_from_slice(&raw_sid);

        let mut cur64 = ByteCursor::with_pointer_size(&buf64, 8);
        let parsed64 = cur64.read_sid("UserSID").unwrap();
        assert_eq!(parsed64, &raw_sid);
        assert!(cur64.is_empty());
    }

    #[test]
    fn test_byte_cursor_unaligned_utf16_after_odd_ansi_string() {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"cmd\0"); // 4 bytes
        buf.push(0xAA); // 1 byte -> offset is now 5 (odd / unaligned!)
        let utf16: Vec<u8> = "powershell.exe -nop\0"
            .encode_utf16()
            .flat_map(|u| u.to_ne_bytes())
            .collect();
        buf.extend_from_slice(&utf16);

        let mut cur = ByteCursor::new(&buf);
        assert_eq!(cur.read_ansi_str("Ansi").unwrap(), "cmd");
        assert_eq!(cur.read_u8("OddPad").unwrap(), 0xAA);
        assert_eq!(cur.position(), 5);
        assert_eq!(
            cur.read_utf16_string("CommandLine").unwrap(),
            "powershell.exe -nop"
        );
        assert!(cur.is_empty());
    }
}
