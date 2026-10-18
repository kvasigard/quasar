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
    let mitigation_note = if event.is_mitigated {
        "In-flight kernel mitigation reduced access rights down to query status."
    } else {
        "Handle rights were NOT stripped in-flight (monitoring/audit mode)."
    };

    return alert(
        "LSASS Memory Access by Untrusted Process",
        `Unsigned process ${event.short_name} (PID ${event.source_pid}) requested PROCESS_VM_READ access to LSASS memory. ${mitigation_note}`
    );
}

return pass();
