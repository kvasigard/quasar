// ==============================================================================
// Rule: LSASS Memory Dump via Comsvcs DLL / Rundll32
// Target Event: ObProcessHandle
// Stage: Detection
// ATT&CK: T1003.001 - OS Credential Dumping: LSASS Memory
// ==============================================================================
// Living-off-the-land minidump generation abusing rundll32.exe and the MiniDump
// export inside comsvcs.dll (or ordinal #24) to extract credentials.
//
// Rundll32 has zero legitimate need to open handles to lsass.exe. This rule flags
// any instance where rundll32 targets LSASS or where comsvcs/minidump CLI parameters
// are observed.

fn rule_info() {
    #{
        name: "lsass_comsvcs_dump",
        event: "ObProcessHandle",
        stage: "detection",
        severity: "critical",
        mitre_tactic: "Credential Access",
        mitre_technique: "T1003.001",
    }
}

// 1. Any rundll32 instance or comsvcs/minidump CLI targeting LSASS with sensitive access rights
let has_sensitive_access = has_mask(event.desired_access, 0x0010)
    || has_mask(event.desired_access, 0x0040)
    || event.desired_access == 0x001FFFFF;

if has_sensitive_access
   && (contains_ic(event.short_name, "rundll32.exe")
       || contains_ic(actor.image_path, "rundll32.exe")
       || contains_ic(actor.command_line, "comsvcs")
       || contains_ic(actor.command_line, "minidump")) {

    let mitigation_note = if event.is_mitigated {
        "In-flight kernel mitigation reduced access rights down to query status."
    } else {
        "Handle rights were NOT stripped in-flight (monitoring/audit mode)."
    };

    return alert(
        "LSASS Memory Access via Rundll32 / Comsvcs DLL",
        `Process ${event.short_name} (PID ${event.source_pid}) attempted to access LSASS memory using living-off-the-land techniques (comsvcs.dll / rundll32). ${mitigation_note}`
    );
}

return pass();
