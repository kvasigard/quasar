//! Context definitions for security alerts and behavioral telemetry correlation.
//!
//! Separates the **Actor** (who executed the operation), the **Target** (entity operated on),
//! and the **Operation** (technical parameters intercepted by kernel or user-mode hooks).

use std::collections::HashMap;
use std::fmt;
use serde::{Deserialize, Serialize};

/// Categorizes the intercepted operation across kernel and user-mode detection domains.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum OperationType {
    /// Object Manager handle creation targeting a process.
    ProcessHandleCreate,
    /// Object Manager handle duplication targeting a process.
    ProcessHandleDuplicate,
    /// Remote thread creation injected into another process address space.
    RemoteThreadCreate,
    /// Direct NT system call executed bypassing user-mode API subsystems.
    DirectSyscall,
    /// Virtual memory protection modification (e.g. RWX allocation).
    VirtualMemoryProtect,
    /// Security access token duplication or impersonation.
    TokenImpersonation,
    /// Custom or future domain operation.
    Other(String),
}

impl fmt::Display for OperationType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProcessHandleCreate => write!(f, "ProcessHandleCreate"),
            Self::ProcessHandleDuplicate => write!(f, "ProcessHandleDuplicate"),
            Self::RemoteThreadCreate => write!(f, "RemoteThreadCreate"),
            Self::DirectSyscall => write!(f, "DirectSyscall"),
            Self::VirtualMemoryProtect => write!(f, "VirtualMemoryProtect"),
            Self::TokenImpersonation => write!(f, "TokenImpersonation"),
            Self::Other(desc) => write!(f, "{desc}"),
        }
    }
}

/// Rich contextual snapshot of the offending actor process.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActorContext {
    /// Process identifier (PID).
    pub pid: u32,
    /// Short executable binary name (e.g. `rundll32.exe`).
    pub name: String,
    /// Fully-qualified binary image file path.
    pub image_path: String,
    /// Full process launch command line arguments.
    pub command_line: String,
    /// Security identifier of the process security token (e.g. `S-1-5-18`).
    pub user_sid: String,
    /// Windows terminal/session identifier.
    pub session_id: u32,
    /// Security token integrity level RID (e.g. `0x3000` High, `0x4000` System).
    pub integrity_level: u32,
    /// Code-signing verification level byte reported by CI.
    pub signature_level: u8,
    /// Kernel Process Protection Level (PPL) byte.
    pub protection: u8,
    /// Parent process identifier.
    pub parent_pid: u32,
    /// Parent executable name.
    pub parent_name: String,
    /// Ancestor execution hierarchy walked backwards from parent to root.
    /// (e.g. `["explorer.exe", "cmd.exe", "rundll32.exe"]`).
    pub ancestry: Vec<String>,
}

/// Generic target description (process, thread, token, or file).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TargetContext {
    /// Target entity PID (or 0 if non-process).
    pub pid: u32,
    /// Target entity name (e.g. `lsass.exe`).
    pub name: String,
    /// Target entity type (e.g. `"Process"`, `"Thread"`, `"Token"`, `"File"`).
    pub entity_type: String,
}

impl Default for TargetContext {
    fn default() -> Self {
        Self {
            pid: 0,
            name: String::new(),
            entity_type: "Process".to_string(),
        }
    }
}

/// Technical parameters of the intercepted operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OperationContext {
    /// Type of operation intercepted.
    pub operation_type: OperationType,
    /// Raw access mask requested by the caller.
    pub desired_access: u32,
    /// Access mask granted after kernel or user-mode mitigation.
    pub granted_access: u32,
    /// Human-readable decomposition of requested access rights.
    pub requested_rights: Vec<String>,
    /// Extensible metadata key-values for operation-specific telemetry.
    pub details: HashMap<String, String>,
}

impl Default for OperationContext {
    fn default() -> Self {
        Self {
            operation_type: OperationType::ProcessHandleCreate,
            desired_access: 0,
            granted_access: 0,
            requested_rights: Vec::new(),
            details: HashMap::new(),
        }
    }
}
