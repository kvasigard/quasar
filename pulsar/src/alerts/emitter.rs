//! Alert emission implementations for console terminals and future UI/SIEM forwarders.

use super::Alert;

/// Trait implemented by destinations consuming generated security alerts.
pub trait AlertEmitter: Send + Sync {
    /// Dispatches an alert instance to the output target.
    fn emit(&self, alert: &Alert);
}

/// Formats and renders security alerts to the terminal with box-drawing characters and ANSI highlights.
pub struct ConsoleEmitter;

impl ConsoleEmitter {
    /// Constructs a new `ConsoleEmitter`.
    pub fn new() -> Self {
        Self
    }

    /// Formats a security alert into a high-contrast Unicode box-drawn string for interactive terminal display.
    ///
    /// # Arguments
    ///
    /// * `alert` - Reference to the [`Alert`] instance to render.
    ///
    /// # Returns
    ///
    /// A multi-line string containing the structured, box-formatted alert.
    pub fn format_alert(alert: &Alert) -> String {
        let width = 88;
        let border_horizontal = "─".repeat(width);

        let tactic = alert.mitre.tactic.to_uppercase();
        let title = &alert.title;
        let severity_str = alert.severity.to_string();
        let mitre_id = &alert.mitre.technique_id;
        let sub_id = alert
            .mitre
            .subtechnique_id
            .as_deref()
            .unwrap_or(mitre_id.as_str());
        let mitre_name = &alert.mitre.technique_name;
        let rule = alert.rule_name.as_deref().unwrap_or("builtin_heuristic");

        let actor = &alert.actor;
        let target = &alert.target;
        let op = &alert.operation;
        let rights_str = if op.requested_rights.is_empty() {
            String::new()
        } else {
            format!(" [{}]", op.requested_rights.join(", "))
        };

        let ancestry_str = if actor.ancestry.is_empty() {
            format!("{} ({})", actor.name, actor.pid)
        } else {
            actor.ancestry.join(" -> ")
        };

        let mut lines = Vec::new();
        lines.push(format!("┌── [ALERT] {tactic} : {title} {border_horizontal}"));
        lines.push(format!("│ Time:        epoch {} ms", alert.timestamp));
        lines.push(format!("│ Severity:    {severity_str}"));
        lines.push(format!("│ MITRE ATT&CK: {sub_id} - {mitre_name}"));
        lines.push(format!("│ Rule:        {rule}"));
        lines.push(format!("├{border_horizontal}"));
        lines.push(format!("│ Actor:       {} (PID: {})", actor.name, actor.pid));
        lines.push(format!("│ Path:        {}", actor.image_path));
        lines.push(format!("│ Command:     {}", actor.command_line));
        lines.push(format!("│ User / SID:  {}", actor.user_sid));
        lines.push(format!("│ Lineage:     {ancestry_str}"));
        lines.push(format!("├{border_horizontal}"));
        lines.push(format!("│ Target:      {} (PID: {}) [Entity: {}]", target.name, target.pid, target.entity_type));
        lines.push(format!("│ Operation:   {} (Target PID: {})", op.operation_type, target.pid));
        lines.push(format!("│ Requested:   {:#010X}{rights_str}", op.desired_access));
        lines.push(format!("│ Granted:     {:#010X}", op.granted_access));
        lines.push(format!("│ Mitigation:  {}", alert.mitigation));
        lines.push(format!("└{border_horizontal}"));

        lines.join("\n")
    }
}

impl Default for ConsoleEmitter {
    fn default() -> Self {
        Self::new()
    }
}

impl AlertEmitter for ConsoleEmitter {
    fn emit(&self, alert: &Alert) {
        let formatted = Self::format_alert(alert);
        // Print alert to stderr/stdout and log via logging framework
        eprintln!("\n{formatted}\n");
        log::warn!(target: "alerts", "[ALERT][{}] {}", alert.mitre.technique_id, alert.title);
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use uuid::Uuid;
    use crate::alerts::{
        ActorContext, Alert, AlertSeverity, MitigationStatus, MitreAttack, OperationContext,
        OperationType, TargetContext,
    };
    use super::*;

    #[test]
    fn test_console_emitter_formatting() {
        let alert = Alert {
            id: Uuid::new_v4(),
            timestamp: 1775731200000,
            severity: AlertSeverity::Critical,
            title: "LSASS Memory Access via Comsvcs DLL".to_string(),
            description: "Process attempted minidump export".to_string(),
            mitre: MitreAttack {
                tactic: "Credential Access".to_string(),
                technique_id: "T1003".to_string(),
                subtechnique_id: Some("T1003.001".to_string()),
                technique_name: "OS Credential Dumping: LSASS Memory".to_string(),
            },
            actor: ActorContext {
                pid: 5120,
                name: "rundll32.exe".to_string(),
                image_path: "C:\\Windows\\System32\\rundll32.exe".to_string(),
                command_line: "rundll32.exe comsvcs.dll, MiniDump 816 C:\\temp\\lsass.dmp full".to_string(),
                user_sid: "S-1-5-18".to_string(),
                session_id: 1,
                integrity_level: 0x4000,
                signature_level: 14,
                protection: 0,
                parent_pid: 4920,
                parent_name: "cmd.exe".to_string(),
                ancestry: vec!["explorer.exe".to_string(), "cmd.exe".to_string(), "rundll32.exe".to_string()],
            },
            target: TargetContext {
                pid: 816,
                name: "lsass.exe".to_string(),
                entity_type: "Process".to_string(),
            },
            operation: OperationContext {
                operation_type: OperationType::ProcessHandleCreate,
                desired_access: 0x001FFFFF,
                granted_access: 0x00001000,
                requested_rights: vec!["PROCESS_ALL_ACCESS".to_string(), "PROCESS_VM_READ".to_string()],
                details: HashMap::new(),
            },
            mitigation: MitigationStatus::Mitigated,
            rule_name: Some("rules/detectors/credential_access/lsass_comsvcs.rhai".to_string()),
            tags: HashMap::new(),
        };

        let formatted = ConsoleEmitter::format_alert(&alert);
        assert!(formatted.contains("[ALERT] CREDENTIAL ACCESS : LSASS Memory Access via Comsvcs DLL"));
        assert!(formatted.contains("CRITICAL"));
        assert!(formatted.contains("T1003.001"));
        assert!(formatted.contains("rundll32.exe (PID: 5120)"));
        assert!(formatted.contains("lsass.exe (PID: 816)"));
        assert!(formatted.contains("0x001FFFFF"));
        assert!(formatted.contains("0x00001000"));
        assert!(formatted.contains("MITIGATED"));
    }
}
