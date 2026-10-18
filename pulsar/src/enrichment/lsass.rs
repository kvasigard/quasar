//! LSASS handle access context enrichment, rights bitmask decoding, and scriptable event model.
//!
//! Enriches raw kernel [`LsassAccessEvent`] records with process lineage, target metadata,
//! decoded access rights flags, and kernel mitigation delta.

use std::collections::HashMap;

use rhai::Scope;
use shared::ring_buffer::LsassAccessEvent;

use crate::alerts::{
    ActorContext, MitigationStatus, OperationContext, OperationType, TargetContext,
};
use crate::enrichment::actor::resolve_actor_context;
use crate::rules::bindings::{RhaiActor, RhaiEvent, RhaiTarget};
use crate::rules::types::{EventType, ScriptableEvent};

/// Fully enriched snapshot of an intercepted kernel handle operation targeting `lsass.exe`.
#[derive(Debug, Clone)]
pub struct EnrichedLsassAccessEvent {
    /// Intercepted raw kernel event payload.
    pub raw: LsassAccessEvent,
    /// Resolved caller process metadata and lineage hierarchy.
    pub actor: ActorContext,
    /// Target entity representation (`lsass.exe`).
    pub target: TargetContext,
    /// Operation parameters and decoded Win32 access rights.
    pub operation: OperationContext,
    /// Mitigation status applied by Singularity in-flight driver callbacks.
    pub mitigation: MitigationStatus,
}

impl ScriptableEvent for EnrichedLsassAccessEvent {
    fn event_type(&self) -> EventType {
        EventType::ObProcessHandle
    }

    fn suppression_key(&self) -> Option<(u32, u32)> {
        // Cache by (PID, desired_access) so repetitive polling (e.g. Taskmgr) bypasses Rhai in < 5ns
        Some((self.raw.source_pid, self.raw.desired_access))
    }

    fn populate_scope(&self, scope: &mut Scope) {
        scope.push("event", RhaiEvent::from_kernel_event(&self.raw));
        scope.push("actor", RhaiActor::from_context(&self.actor));
        scope.push("target", RhaiTarget::from_context(&self.target));
    }
}

/// Decodes Win32 process access mask bitflags into human-readable right strings.
///
/// # Arguments
///
/// * `mask` - Bitmask representing requested or granted access rights.
///
/// # Returns
///
/// Vector of standard Win32 right names (e.g. `PROCESS_VM_READ`, `PROCESS_ALL_ACCESS`).
pub fn decode_handle_rights(mask: u32) -> Vec<String> {
    let mut rights = Vec::new();
    if mask & 0x0001 != 0 { rights.push("PROCESS_TERMINATE".to_string()); }
    if mask & 0x0002 != 0 { rights.push("PROCESS_CREATE_THREAD".to_string()); }
    if mask & 0x0008 != 0 { rights.push("PROCESS_VM_OPERATION".to_string()); }
    if mask & 0x0010 != 0 { rights.push("PROCESS_VM_READ".to_string()); }
    if mask & 0x0020 != 0 { rights.push("PROCESS_VM_WRITE".to_string()); }
    if mask & 0x0040 != 0 { rights.push("PROCESS_DUP_HANDLE".to_string()); }
    if mask & 0x0080 != 0 { rights.push("PROCESS_CREATE_PROCESS".to_string()); }
    if mask & 0x0100 != 0 { rights.push("PROCESS_SET_QUOTA".to_string()); }
    if mask & 0x0200 != 0 { rights.push("PROCESS_SET_INFORMATION".to_string()); }
    if mask & 0x0400 != 0 { rights.push("PROCESS_QUERY_INFORMATION".to_string()); }
    if mask & 0x0800 != 0 { rights.push("PROCESS_SUSPEND_RESUME".to_string()); }
    if mask & 0x1000 != 0 { rights.push("PROCESS_QUERY_LIMITED_INFORMATION".to_string()); }
    if mask & 0x00100000 != 0 { rights.push("SYNCHRONIZE".to_string()); }
    if (mask & 0x001FFFFF) == 0x001FFFFF { rights.push("PROCESS_ALL_ACCESS".to_string()); }
    rights
}

/// Enriches a raw kernel [`LsassAccessEvent`] into an [`EnrichedLsassAccessEvent`].
///
/// Correlates the caller PID against historical process generations in `SystemState`,
/// decodes the requested access mask into explicit right names, and computes the kernel
/// mitigation status based on granted vs. desired access rights.
///
/// # Arguments
///
/// * `event` - Raw event received from the driver ring buffer.
///
/// # Returns
///
/// A populated [`EnrichedLsassAccessEvent`] ready for rule evaluation and alerting.
pub fn enrich_lsass_access(event: &LsassAccessEvent) -> EnrichedLsassAccessEvent {
    let source_name = String::from_utf8_lossy(&event.short_name);
    let cleaned_name = source_name.trim_matches('\0');
    let op_type = if event.operation == 1 {
        OperationType::ProcessHandleCreate
    } else {
        OperationType::ProcessHandleDuplicate
    };

    let mut actor = resolve_actor_context(event.source_pid, cleaned_name);
    actor.integrity_level = event.integrity_level;
    actor.signature_level = event.signature_level;
    actor.protection = event.protection;

    let target = TargetContext {
        pid: event.target_pid,
        name: "lsass.exe".to_string(),
        entity_type: "Process".to_string(),
    };

    let requested_rights = decode_handle_rights(event.desired_access);
    let operation = OperationContext {
        operation_type: op_type,
        desired_access: event.desired_access,
        granted_access: event.granted_access,
        requested_rights,
        details: HashMap::new(),
    };

    let mitigation = if event.desired_access != event.granted_access {
        MitigationStatus::Mitigated
    } else {
        MitigationStatus::AuditedOnly
    };

    EnrichedLsassAccessEvent {
        raw: *event,
        actor,
        target,
        operation,
        mitigation,
    }
}
