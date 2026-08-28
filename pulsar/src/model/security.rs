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
