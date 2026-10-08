//! Analytical detection sink monitoring kernel Object Manager handle operations.
//!
//! Subscribes to [`HandlePreOpEvent`] telemetry emitted by the Singularity KMDF driver,
//! auditing handle creation and duplication requests targeting sensitive system processes
//! such as `lsass.exe` to detect credential dumping (e.g. Mimikatz, MiniDumpWriteDump).

use shared::ring_buffer::HandlePreOpEvent;

use crate::pipeline::EventListener;

/// Analytical detection sink for unauthorized or suspicious handle access.
pub struct TamperDetectionSink;

impl TamperDetectionSink {
    /// Constructs a new `TamperDetectionSink`.
    pub fn new() -> Self {
        Self
    }
}

impl Default for TamperDetectionSink {
    fn default() -> Self {
        Self::new()
    }
}

impl EventListener for TamperDetectionSink {
    fn on_handle_pre_op(&self, event: &HandlePreOpEvent) {
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

        let has_dump_rights = (event.desired_access & (PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_DUP_HANDLE)) != 0;

        if has_dump_rights {
            log::warn!(
                target: "tamper_sink",
                "[ALERT][CREDENTIAL_ACCESS] Suspicious handle [{op_name}] targeting PID {} from PID {} ({}) | Access: {:#010X}",
                event.target_pid,
                event.source_pid,
                cleaned_name,
                event.desired_access
            );
        } else {
            log::debug!(
                target: "tamper_sink",
                "[AUDIT][HANDLE_OP] Handle [{op_name}] targeting PID {} from PID {} ({}) | Access: {:#010X}",
                event.target_pid,
                event.source_pid,
                cleaned_name,
                event.desired_access
            );
        }
    }
}
