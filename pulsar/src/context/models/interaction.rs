//! Interaction taxonomy and cross-entity relationship models.

use crate::context::identity::{EntityId, InteractionId, ProcessKey};

/// Specific technique observed in a code injection or tampering attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InjectionTechnique {
    /// CreateRemoteThread API injection into a remote process.
    ClassicRemoteThread,
    /// Asynchronous Procedure Call queuing to a remote thread.
    QueueUserApc,
    /// Thread context hijack via SetThreadContext.
    SetThreadContext,
    /// Process Hollowing (unmapping original executable section).
    ProcessHollowing,
    /// Process Ghosting (deleting file before creating section).
    ProcessGhosting,
    /// Overwriting legitimate mapped DLLs in memory.
    ModuleStomping,
    /// Early Cascade / Early Bird injection variant.
    EarlyCascadeInjection,
    /// Unclassified cross-process virtual memory write.
    UnknownCrossProcessWrite,
}

/// Execution trigger that caused injected payload to execute.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExecutionTrigger {
    /// Remote thread creation trigger.
    NtCreateThreadEx,
    /// APC queue execution trigger.
    QueueUserApc,
    /// Window message hook trigger.
    SetWindowHook,
    /// Thread resumption trigger.
    ThreadResume,
    /// Direct function pointer call trigger.
    DirectExecution,
}

/// Detailed context for a detected code injection interaction.
#[derive(Debug, Clone, PartialEq)]
pub struct InjectionDetails {
    /// Inferred or identified injection technique.
    pub technique: InjectionTechnique,
    /// Target base address in remote memory.
    pub target_base_address: Option<u64>,
    /// Number of bytes allocated or written.
    pub allocated_size: Option<usize>,
    /// How the payload was triggered.
    pub execution_trigger: Option<ExecutionTrigger>,
    /// Number of sequential attack stages correlated.
    pub stages_observed: u8,
}

/// Detailed context for a cross-process handle duplication event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandleDupDetails {
    /// Source handle descriptor.
    pub source_handle: u64,
    /// Target duplicated handle descriptor.
    pub target_handle: u64,
    /// Granted access mask.
    pub granted_access: u32,
}

/// Detailed context for cross-process token manipulation or theft.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenImpersonationDetails {
    /// Target security identifier string.
    pub target_user_sid: String,
    /// Target integrity level.
    pub target_integrity: String,
    /// Whether the token was duplicated.
    pub is_duplicate: bool,
}

/// Detailed context for memory tampering or shellcode staging.
#[derive(Debug, Clone, PartialEq)]
pub struct MemoryTamperingDetails {
    /// Target virtual base address.
    pub target_base_address: u64,
    /// Size of the modified memory region.
    pub region_size: usize,
    /// Memory protection before modification.
    pub old_protection: u32,
    /// New memory protection (e.g. PAGE_EXECUTE_READWRITE).
    pub new_protection: u32,
    /// Whether the region is unbacked by a physical image.
    pub is_unbacked: bool,
}

/// High-level typed categories of interactions between system entities.
#[derive(Debug, Clone, PartialEq)]
pub enum InteractionKind {
    /// Code injection into another process address space.
    ProcessInjection(InjectionDetails),
    /// Handle duplication into/from another process.
    HandleDuplication(HandleDupDetails),
    /// Security token impersonation or theft.
    TokenImpersonation(TokenImpersonationDetails),
    /// Direct memory modification / RWX allocation in another process.
    MemoryTampering(MemoryTamperingDetails),
    /// Parent spawned a child process.
    ProcessSpawn,
    /// Thread created in remote process.
    RemoteThreadCreation,
    /// Sensitive file access (e.g. LSASS minidump, SAM hive access).
    SensitiveFileAccess(String),
}

/// Confidence rating for a registered interaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ConfidenceLevel {
    /// Low confidence heuristic.
    Low,
    /// Moderate confidence pattern.
    Medium,
    /// High confidence multi-stage sequence.
    High,
    /// Confirmed malicious behavior.
    Confirmed,
}

/// Complete timestamped record representing an interaction between two entities.
#[derive(Debug, Clone, PartialEq)]
pub struct InteractionRecord {
    /// Unique synthetic ID for this interaction event.
    pub id: InteractionId,
    /// Timestamp when this interaction was registered (FILETIME 100ns ticks).
    pub timestamp: i64,
    /// Type of interaction.
    pub kind: InteractionKind,
    /// Originator / actor entity.
    pub source: EntityId,
    /// Target entity that received the action.
    pub target: EntityId,
    /// Detection confidence level.
    pub confidence: ConfidenceLevel,
    /// Human-readable contextual description.
    pub description: String,
}

impl InteractionRecord {
    /// Creates a new interaction record.
    ///
    /// # Arguments
    ///
    /// * `kind` - The category and payload of the interaction.
    /// * `source` - The actor entity.
    /// * `target` - The receiving entity.
    /// * `timestamp` - Detection timestamp.
    /// * `confidence` - Confidence rating.
    /// * `description` - Contextual description text.
    ///
    /// # Returns
    ///
    /// An initialized [`InteractionRecord`].
    pub fn new(
        kind: InteractionKind,
        source: EntityId,
        target: EntityId,
        timestamp: i64,
        confidence: ConfidenceLevel,
        description: impl Into<String>,
    ) -> Self {
        Self {
            id: InteractionId::new(),
            timestamp,
            kind,
            source,
            target,
            confidence,
            description: description.into(),
        }
    }

    /// Convenience helper to extract source ProcessKey if source is a process.
    ///
    /// # Returns
    ///
    /// `Some(ProcessKey)` if the source is a process entity, otherwise `None`.
    pub fn source_process_key(&self) -> Option<ProcessKey> {
        self.source.as_process()
    }

    /// Convenience helper to extract target ProcessKey if target is a process.
    ///
    /// # Returns
    ///
    /// `Some(ProcessKey)` if the target is a process entity, otherwise `None`.
    pub fn target_process_key(&self) -> Option<ProcessKey> {
        self.target.as_process()
    }

    /// Returns `true` if this interaction is a ProcessInjection.
    ///
    /// # Returns
    ///
    /// `true` if `self.kind` is [`InteractionKind::ProcessInjection`].
    pub fn is_injection(&self) -> bool {
        matches!(self.kind, InteractionKind::ProcessInjection(_))
    }
}
