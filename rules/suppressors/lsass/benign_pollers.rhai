// ==============================================================================
// Rule: Routine LSASS Diagnostic Polling Suppressor
// Target Event: ObProcessHandle
// Stage: Suppression
// Target: lsass.exe
// ==============================================================================
// Authentic Windows and hypervisor diagnostics periodically query LSASS with access mask 0x1410:
//   PROCESS_QUERY_LIMITED_INFORMATION (0x1000) | PROCESS_QUERY_INFORMATION (0x0400) | PROCESS_VM_READ (0x0010)
// Singularity driver callbacks strip PROCESS_VM_READ (0x0010) in-flight, granting only 0x1000.
//
// Anti-Bypass Protections:
// 1. Strict Access Mask: Only exact diagnostic query mask (0x1410) is eligible.
// 2. Command Line Audit: Rejects any invocation carrying dump or credential theft arguments.
// 3. Absolute Path Verification: Enforces authentic OS directory boundaries (System32 / Program Files).
// 4. Token Integrity Gates: Requires minimum mandatory integrity levels appropriate for each tool.

fn rule_info() {
    #{
        name: "lsass_benign_pollers",
        event: "ObProcessHandle",
        stage: "suppression",
    }
}

// Only evaluate against routine query masks (0x1410)
if event.desired_access != 0x1410 {
    return pass();
}

// Reject any suspicious command-line parameters (e.g. minidump, comsvcs, sekurlsa)
if contains_ic(actor.command_line, "dump")
   || contains_ic(actor.command_line, "minidump")
   || contains_ic(actor.command_line, "comsvcs")
   || contains_ic(actor.command_line, "sekurlsa") {
    return pass();
}

let name = event.short_name.to_lower();

// 1. Windows Task Manager
// - Must be taskmgr.exe
// - Must reside in System32 to prevent path spoofing
// - Must run at Medium integrity (0x2000) or higher
if name == "taskmgr.exe" {
    if starts_with_ic(actor.image_path, "c:\\windows\\system32\\")
       && event.integrity_level >= 0x2000 {
        return suppress("Authentic Windows Task Manager diagnostic query", 0);
    }
}

// 2. WMI Provider Host
// - Must be wmiprvse.exe
// - Must reside in System32\wbem
// - Must run as High/System integrity (0x3000+)
if name == "wmiprvse.exe" {
    if starts_with_ic(actor.image_path, "c:\\windows\\system32\\wbem\\")
       && event.integrity_level >= 0x3000 {
        return suppress("Authentic WMI Provider Host diagnostic query", 0);
    }
}

// 3. VMware Tools Guest Agent
// - Must be vmtoolsd.exe
// - Must reside in Program Files\VMware
// - Must run as System integrity (0x4000)
if name == "vmtoolsd.exe" {
    if starts_with_ic(actor.image_path, "c:\\program files\\vmware\\")
       && event.integrity_level >= 0x4000 {
        return suppress("Authentic VMware Tools guest diagnostic query", 0);
    }
}

return pass();
