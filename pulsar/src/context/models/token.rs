//! Security token, integrity levels, and privilege model.

use std::collections::HashSet;

/// Windows Process / Thread Security Token Integrity Level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum IntegrityLevel {
    Untrusted,
    Low,
    Medium,
    High,
    System,
    ProtectedProcess,
    #[default]
    Unknown,
}

/// Token privilege state (e.g. `SeDebugPrivilege`, `SeTcbPrivilege`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivilegeState {
    /// Name of the security privilege.
    pub name: String,
    /// Whether the privilege is enabled.
    pub is_enabled: bool,
}

/// Execution security token representation.
#[derive(Debug, Clone, Default)]
pub struct TokenContext {
    /// Security Identifier (SID) string of the token owner (e.g., "S-1-5-18").
    pub user_sid: Option<String>,
    /// Resolved account name (e.g., "NT AUTHORITY\\SYSTEM" or "DESKTOP-XYZ\\User").
    pub user_name: Option<String>,
    /// Session ID where this token is active.
    pub session_id: u32,
    /// Integrity level of the process or impersonated thread.
    pub integrity: IntegrityLevel,
    /// Whether the token is elevated (administrator / system).
    pub is_elevated: bool,
    /// Set of enabled privilege names on this token.
    pub enabled_privileges: HashSet<String>,
}

impl TokenContext {
    /// Creates a new default `TokenContext`.
    ///
    /// # Returns
    ///
    /// An empty, default [`TokenContext`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Checks whether a specific privilege is enabled on this token.
    ///
    /// # Arguments
    ///
    /// * `priv_name` - The privilege name to evaluate.
    ///
    /// # Returns
    ///
    /// `true` if the privilege is held and enabled.
    pub fn has_privilege(&self, priv_name: &str) -> bool {
        self.enabled_privileges.contains(priv_name)
    }

    /// Enables a privilege on this token context.
    ///
    /// # Arguments
    ///
    /// * `priv_name` - The privilege name to enable.
    pub fn enable_privilege(&mut self, priv_name: impl Into<String>) {
        self.enabled_privileges.insert(priv_name.into());
    }
}
