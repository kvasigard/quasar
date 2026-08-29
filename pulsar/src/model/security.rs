//! Security and identity domain models.

use std::fmt;

/// Strongly-typed Windows Security Identifier (SID).
/// Formatted as standard SDDL string (e.g. `S-1-5-18`, `S-1-5-21-...`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Sid(pub String);

impl TryFrom<&[u8]> for Sid {
    type Error = &'static str;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() < 8 {
            return Err("SID buffer too short for header");
        }

        let revision = bytes[0];
        let sub_auth_count = bytes[1] as usize;
        let expected_len = 8 + (sub_auth_count * 4);

        if bytes.len() < expected_len {
            return Err("SID buffer truncated");
        }

        // 6-byte identifier authority as 48-bit big-endian integer
        let mut auth_bytes = [0u8; 8];
        auth_bytes[2..8].copy_from_slice(&bytes[2..8]);
        let authority = u64::from_be_bytes(auth_bytes);

        let mut sid_str = format!("S-{}-{}", revision, authority);

        for i in 0..sub_auth_count {
            let start = 8 + (i * 4);
            let sub_auth = u32::from_ne_bytes(bytes[start..start + 4].try_into().unwrap());
            sid_str.push_str(&format!("-{}", sub_auth));
        }

        Ok(Sid(sid_str))
    }
}

impl fmt::Display for Sid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verifies binary SID decoding with 48-bit big-endian authority and multiple 32-bit sub-authorities into SDDL format.
    /// Crucial for user context attribution (e.g., SYSTEM vs Administrator) in behavioral detection rules.
    #[test]
    fn test_sid_binary_to_sddl_string() {
        // S-1-5-21-100-200-300-500 (Revision: 1, SubAuthCount: 5, Authority: 5)
        let mut bytes = vec![1u8, 5, 0, 0, 0, 0, 0, 5];
        bytes.extend_from_slice(&21u32.to_ne_bytes());
        bytes.extend_from_slice(&100u32.to_ne_bytes());
        bytes.extend_from_slice(&200u32.to_ne_bytes());
        bytes.extend_from_slice(&300u32.to_ne_bytes());
        bytes.extend_from_slice(&500u32.to_ne_bytes());

        let sid = Sid::try_from(bytes.as_slice()).expect("Valid domain SID must parse");
        assert_eq!(sid.0, "S-1-5-21-100-200-300-500");
    }

    /// Asserts that SID byte arrays missing header or sub-authority payload fail safely with specific errors.
    /// Prevents panic unwinds in ETW consumer threads when inspecting tokens from corrupted or terminating processes.
    #[test]
    fn test_sid_truncation_errors() {
        // Less than 8 bytes header
        assert_eq!(Sid::try_from(&[1u8, 1, 0][..]), Err("SID buffer too short for header"));

        // Header claims 2 sub-authorities (16 bytes expected), but only 12 bytes given
        let truncated = [1u8, 2, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
        assert_eq!(Sid::try_from(&truncated[..]), Err("SID buffer truncated"));
    }
}

