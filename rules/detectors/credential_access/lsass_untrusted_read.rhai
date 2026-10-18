// ==============================================================================
// Rule: Unauthorized In-Memory LSASS Access by Untrusted Binary
// Target Event: ObProcessHandle
// Stage: Detection
// ATT&CK: T1003.001 - OS Credential Dumping: LSASS Memory
// ==============================================================================
// Unsigned or non-Microsoft binary attempting PROCESS_VM_READ (0x0010) on LSASS.
// Signature level < 8 indicates unsigned, test-signed, or untrusted third-party code.

fn rule_info() {
    #{
        name: "lsass_untrusted_read",
        event: "ObProcessHandle",
        stage: "detection",
        severity: "high",
        mitre_tactic: "Credential Access",
        mitre_technique: "T1003.001",
    }
}

if event.signature_level < 8 && has_mask(event.desired_access, 0x0010) {
    return alert(
        "High",
        "LSASS Memory Access by Untrusted Process",
        `Unsigned process ${event.short_name} (PID ${event.source_pid}) requested PROCESS_VM_READ access to LSASS memory. In-flight kernel mitigation reduced access rights down to query status.`,
        "Credential Access",
        "T1003.001"
    );
}

return pass();
