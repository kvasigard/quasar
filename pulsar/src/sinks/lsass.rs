//! Analytical detection sink monitoring kernel Object Manager handle operations targeting `lsass.exe`.
//!
//! Subscribes to [`LsassAccessEvent`] telemetry emitted by the Singularity KMDF driver,
//! auditing handle creation and duplication requests targeting `lsass.exe`
//! to detect credential dumping (e.g. Mimikatz, MiniDumpWriteDump).

use shared::ring_buffer::LsassAccessEvent;

use crate::pipeline::EventListener;

/// Analytical detection sink for unauthorized or suspicious LSASS handle access.
pub struct LsassAccessSink;

impl LsassAccessSink {
    /// Constructs a new `LsassAccessSink`.
    pub fn new() -> Self {
        Self
    }
}

impl Default for LsassAccessSink {
    fn default() -> Self {
        Self::new()
    }
}

impl EventListener for LsassAccessSink {
    fn on_lsass_access(&self, event: &LsassAccessEvent) {
        let source_name = String::from_utf8_lossy(&event.short_name);
        let cleaned_name = source_name.trim_matches('\0');
        let op_name = if event.operation == 1 {
            "CREATE"
        } else {
            "DUPLICATE"
        };

        // Standard sensitive process access rights associated with memory dumping / injection:
        // PROCESS_VM_READ (0x0010), PROCESS_VM_WRITE (0x0020), PROCESS_DUP_HANDLE (0x0040), PROCESS_ALL_ACCESS (0x1FFFFF)
        const PROCESS_VM_READ: u32 = 0x0010;
        const PROCESS_VM_WRITE: u32 = 0x0020;
        const PROCESS_DUP_HANDLE: u32 = 0x0040;

        let has_dump_rights =
            (event.desired_access & (PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_DUP_HANDLE)) != 0;
        let is_mitigated = event.desired_access != event.granted_access;

        if has_dump_rights {
            log::warn!(
                target: "lsass_sink",
                "[ALERT][CREDENTIAL_ACCESS] Suspicious LSASS handle [{op_name}] targeting PID {} from PID {} ({}) | Requested: {:#010X} | Granted: {:#010X} [Mitigated: {}] | Sig: {:#04X}, Integrity: {:#06X}, PPL: {:#04X}",
                event.target_pid,
                event.source_pid,
                cleaned_name,
                event.desired_access,
                event.granted_access,
                is_mitigated,
                event.signature_level,
                event.integrity_level,
                event.protection
            );
        } else {
            log::debug!(
                target: "lsass_sink",
                "[AUDIT][LSASS_ACCESS] LSASS handle [{op_name}] targeting PID {} from PID {} ({}) | Requested: {:#010X} | Granted: {:#010X} [Mitigated: {}] | Sig: {:#04X}, Integrity: {:#06X}, PPL: {:#04X}",
                event.target_pid,
                event.source_pid,
                cleaned_name,
                event.desired_access,
                event.granted_access,
                is_mitigated,
                event.signature_level,
                event.integrity_level,
                event.protection
            );
        }
    }
}
