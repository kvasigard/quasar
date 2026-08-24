//! Direct System Call evasion and unbacked memory syscall detection sink.

use std::sync::Arc;
use crate::alerts::{alert_manager, AlertRecord, AlertSeverity};
use crate::context::models::interaction::ConfidenceLevel;
use crate::context::models::module::LoadedModule;
use crate::context::system_context;
use crate::pipeline::event::{CorrelatedSyscallEvent, Event};
use crate::pipeline::Subscriber;

/// Detection sink identifying direct system calls, unbacked memory syscall stubs, and hooked binaries.
#[derive(Debug, Default, Clone)]
pub struct DirectSyscallSink;

impl DirectSyscallSink {
    /// Creates a new `DirectSyscallSink` instance.
    pub fn new() -> Self {
        Self
    }

    /// Core heuristic analyzing the resolved call stack for Direct Syscall patterns.
    ///
    /// # Direct Syscall Detection Heuristic:
    /// In legitimate Windows applications, syscall transitions from User Mode to Kernel Mode
    /// pass through `ntdll.dll` (or `win32u.dll`).
    ///
    /// When an attacker executes Direct Syscalls (e.g. Hell's Gate, SysWhispers, Halo's Gate),
    /// the instruction pointer immediately preceding kernel transition originates from
    /// an unbacked memory stub or directly from unauthorized non-system binaries.
    #[tracing::instrument(name = "analyze_direct_syscall", skip(self, event), level = "trace")]
    fn analyze_direct_syscall(&self, event: &CorrelatedSyscallEvent) {
        // In 64-bit Windows, User Space ends at 0x00007FFFFFFFFFFF.
        const USER_SPACE_MIN: u64 = 0x10000;
        const USER_SPACE_MAX: u64 = 0x00007FFFFFFFFFFF;

        let user_frames: Vec<u64> = event
            .frames
            .iter()
            .copied()
            .filter(|&frame| (USER_SPACE_MIN..=USER_SPACE_MAX).contains(&frame))
            .collect();

        let Some(&top_user_ptr) = user_frames.first() else {
            return;
        };

        let ctx = system_context();
        let Some(proc) = ctx.process(event.pid) else {
            return;
        };

        // Guard against unpopulated context during early process startup or driver cold-start:
        // If neither process-local modules nor global system modules are populated,
        // we lack baseline telemetry to reliably evaluate evasion.
        let has_local_modules = !proc.inner.loaded_modules.read().is_empty();
        let has_system_modules = !ctx.system_modules.read().is_empty();
        if !has_local_modules && !has_system_modules {
            if log::log_enabled!(log::Level::Trace) {
                log::trace!(
                    target: "direct_sys",
                    "Suppressed syscall evaluation for PID {}: modules not yet populated",
                    event.pid
                );
            }
            return;
        }

        // Helper closure to resolve module for this process or fallback to global system modules
        let resolve_module = |addr: u64| -> Option<LoadedModule> {
            proc.find_module_by_address(addr)
                .or_else(|| ctx.find_system_module_by_address(addr))
        };

        // Check whether ANY user-mode frame in the call stack transitions through a legitimate system DLL (ntdll, win32u)
        let has_system_dll_frame = user_frames.iter().any(|&frame| {
            if let Some(module) = resolve_module(frame) {
                let mod_name = module.image_name().to_lowercase();
                module.is_system() || mod_name.contains("ntdll") || mod_name.contains("win32u")
            } else {
                false
            }
        });

        // 1. In-memory loaded module interval resolution (< 30 ns) with system DLL fallback
        if let Some(top_module) = resolve_module(top_user_ptr) {
            let mod_name = top_module.image_name().to_lowercase();
            let is_legitimate_provider = top_module.is_system()
                || mod_name.contains("ntdll")
                || mod_name.contains("win32u");

            if is_legitimate_provider {
                // Validate against pure-Rust PE export directory on FileRecord if enriched
                let rva = (top_user_ptr.saturating_sub(top_module.base_address)) as u32;

                if let Some(file_key) = top_module.file_key()
                    && let Some(pe_info) = ctx.file_pe_info(file_key)
                    && pe_info.find_export_by_rva(rva).is_none()
                {
                    // Check if RVA is within an executable code section of the system DLL
                    let is_exec_sec = pe_info
                        .find_section_by_rva(rva)
                        .map(|s| s.is_executable())
                        .unwrap_or(true);

                    if !is_exec_sec {
                        proc.pin();
                        alert_manager().emit(
                            AlertRecord::new(
                                AlertSeverity::High,
                                "Defense Evasion",
                                "Tampered/Hooked Syscall in Non-Executable Section",
                                format!(
                                    "Process [{}] executed syscall from non-executable section of module [{}] at {:#x}",
                                    proc.image_name(),
                                    top_module.image_name(),
                                    top_user_ptr
                                ),
                                proc.key(),
                                ConfidenceLevel::High,
                                event.timestamp,
                            )
                            .with_mitre("T1055.012")
                            .with_evidence("module", top_module.image_name())
                            .with_evidence("rva", format!("{:#x}", rva))
                            .with_evidence("address", format!("{:#x}", top_user_ptr)),
                        );
                    }
                }
            } else if !has_system_dll_frame {
                // The syscall originated inside an on-disk binary, and the call stack contains ZERO frames from ntdll/win32u (e.g. embedded syscall stub)
                proc.pin();
                alert_manager().emit(
                    AlertRecord::new(
                        AlertSeverity::High,
                        "Defense Evasion",
                        "Direct System Call Evasion",
                        format!(
                            "Process [{}] executed direct syscall from unauthorized non-system module [{}] at {:#x}",
                            proc.image_name(),
                            top_module.image_name(),
                            top_user_ptr
                        ),
                        proc.key(),
                        ConfidenceLevel::High,
                        event.timestamp,
                    )
                    .with_mitre("T1106")
                    .with_evidence("module", top_module.image_name())
                    .with_evidence("address", format!("{:#x}", top_user_ptr)),
                );
            }
        } else if !has_system_dll_frame {
            // Return address is in unbacked memory AND zero system DLL frames were present in the call stack
            proc.pin();
            alert_manager().emit(
                AlertRecord::new(
                    AlertSeverity::Critical,
                    "Defense Evasion",
                    "Unbacked Memory Direct System Call",
                    format!(
                        "Process [{}] executed direct syscall from unbacked memory (heap/shellcode) at {:#x}",
                        proc.image_name(),
                        top_user_ptr
                    ),
                    proc.key(),
                    ConfidenceLevel::Confirmed,
                    event.timestamp,
                )
                .with_mitre("T1055")
                .with_evidence("address", format!("{:#x}", top_user_ptr)),
            );
        }
    }
}

impl Subscriber for DirectSyscallSink {
    /// Subscribes strictly to correlated system call stack events.
    fn is_interested(&self, event: &Event) -> bool {
        matches!(event, Event::CorrelatedSyscall(_))
    }

    /// Evaluates correlated syscall stack events.
    fn on_event(&self, event: &Arc<Event>) {
        if let Event::CorrelatedSyscall(syscall_event) = &**event {
            self.analyze_direct_syscall(syscall_event);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::identity::ProcessKey;
    use crate::context::models::file::FileFormatInfo;
    use crate::context::models::module::LoadedModule;
    use crate::context::models::process::ProcessContext;
    use crate::context::CONTEXT;
    use crate::helpers::pe::{PeExport, PeExportDirectory, PeInfo, PeSection};

    #[test]
    fn test_direct_sys_sink_subscriber_filtering() {
        let sink = DirectSyscallSink::new();
        let syscall_event = Event::CorrelatedSyscall(CorrelatedSyscallEvent {
            pid: 1234,
            tid: 5678,
            timestamp: 1000,
            syscall_address: Some(0x28),
            frames: vec![0x7FFF_1234_5678],
        });

        assert!(sink.is_interested(&syscall_event));
    }

    #[test]
    fn test_direct_sys_sink_cold_start_suppression() {
        let sink = DirectSyscallSink::new();
        let pid = 7788;
        let proc_key = ProcessKey::new();
        let proc = ProcessContext::new(proc_key, None, pid, 1000, 100);
        proc.set_image_name("fresh_startup.exe");
        CONTEXT.insert_process(proc);

        // Process has 0 loaded modules and system_modules is empty -> should be suppressed
        let unbacked_event = Arc::new(Event::CorrelatedSyscall(CorrelatedSyscallEvent {
            pid,
            tid: 1001,
            timestamp: 1010,
            syscall_address: Some(0xFFFF_F800_0000_0000),
            frames: vec![0xFFFF_F800_0000_1234, 0x0000_7FFF_9999_0000],
        }));

        let alerts_before = alert_manager().len();
        sink.on_event(&unbacked_event);
        let alerts_after = alert_manager().len();

        // No false positive alert emitted
        assert_eq!(alerts_before, alerts_after);
    }

    #[test]
    fn test_direct_sys_sink_evaluation_paths() {
        let sink = DirectSyscallSink::new();
        let pid = 8888;
        let proc_key = ProcessKey::new();
        let proc = ProcessContext::new(proc_key, None, pid, 1000, 100);
        proc.set_image_name("testapp.exe");

        // 1. Module A: ntdll.dll with valid PeInfo export
        let ntdll_base = 0x0000_7FFF_1000_0000u64;
        let ntdll_file_ctx = CONTEXT.get_or_create_file(r"C:\Windows\System32\ntdll.dll", 1000);
        let ntdll_file_key = ntdll_file_ctx.key;

        let mut by_name = std::collections::HashMap::new();
        by_name.insert("NtWriteVirtualMemory".to_string(), 0x1050);

        let pe_info = Arc::new(PeInfo {
            is_64bit: true,
            machine: 0x8664,
            characteristics: 0x2000,
            subsystem: 3,
            image_base: ntdll_base,
            size_of_image: 0x100000,
            entry_point_rva: 0x1000,
            size_of_headers: 0x1000,
            sections: vec![
                PeSection {
                    name: ".text".to_string(),
                    virtual_address: 0x1000,
                    virtual_size: 0x80000,
                    raw_data_offset: 0x1000,
                    raw_data_size: 0x80000,
                    characteristics: 0x60000020, // Executable
                },
                PeSection {
                    name: ".data".to_string(),
                    virtual_address: 0x81000,
                    virtual_size: 0x10000,
                    raw_data_offset: 0x81000,
                    raw_data_size: 0x10000,
                    characteristics: 0xC0000040, // Non-executable
                },
            ],
            exports: Some(PeExportDirectory {
                dll_name: Some("ntdll.dll".to_string()),
                export_table_rva: 0x90000,
                export_table_size: 0x10000,
                ordinal_base: 1,
                exports: vec![PeExport {
                    name: Some("NtWriteVirtualMemory".to_string()),
                    ordinal: 1,
                    rva: 0x1050,
                    forwarder: None,
                }],
                by_name,
                by_ordinal: std::collections::HashMap::new(),
            }),
        });

        ntdll_file_ctx.set_format_info(FileFormatInfo::Pe(pe_info));

        let mod_ntdll = LoadedModule::new(
            ntdll_base,
            0x100000,
            "ntdll.dll".to_string(),
            Some(ntdll_file_key),
            1000,
            0,
            ntdll_base,
            true,
        );
        proc.record_module_load(mod_ntdll);

        // 2. Module B: malware.exe (non-system module)
        let malware_base = 0x0000_7FFF_2000_0000u64;
        let mod_malware = LoadedModule::new(
            malware_base,
            0x50000,
            "malware.exe".to_string(),
            None,
            1000,
            0,
            malware_base,
            false,
        );
        proc.record_module_load(mod_malware);

        CONTEXT.insert_process(proc);

        // Scenario A: Legitimate call originating inside ntdll at exported RVA 0x1050
        let legit_addr = ntdll_base + 0x1050;
        let legit_event = Arc::new(Event::CorrelatedSyscall(CorrelatedSyscallEvent {
            pid,
            tid: 1001,
            timestamp: 1050,
            syscall_address: Some(0xFFFF_F800_BF84_A090),
            frames: vec![0xFFFF_F800_0000_1234, legit_addr, 0x0000_7FFF_2000_1000],
        }));
        sink.on_event(&legit_event);

        // Scenario B: Evasive direct syscall originating from malware.exe (no ntdll frame)
        let malware_addr = malware_base + 0x1500;
        let evasive_event = Arc::new(Event::CorrelatedSyscall(CorrelatedSyscallEvent {
            pid,
            tid: 1002,
            timestamp: 1060,
            syscall_address: Some(0xFFFF_F800_BF84_A090),
            frames: vec![0xFFFF_F800_0000_1234, malware_addr],
        }));
        sink.on_event(&evasive_event);

        // Scenario C: Evasive direct syscall originating from unbacked memory (0x0000_7FFF_9999_0000)
        let unbacked_addr = 0x0000_7FFF_9999_0000u64;
        let unbacked_event = Arc::new(Event::CorrelatedSyscall(CorrelatedSyscallEvent {
            pid,
            tid: 1003,
            timestamp: 1070,
            syscall_address: Some(0xFFFF_F800_BF84_A090),
            frames: vec![0xFFFF_F800_0000_1234, unbacked_addr],
        }));
        sink.on_event(&unbacked_event);

        // Scenario D: Hooked/tampered syscall in non-executable .data section of ntdll (RVA 0x81500)
        let hooked_addr = ntdll_base + 0x81500;
        let hooked_event = Arc::new(Event::CorrelatedSyscall(CorrelatedSyscallEvent {
            pid,
            tid: 1004,
            timestamp: 1080,
            syscall_address: Some(0xFFFF_F800_BF84_A090),
            frames: vec![0xFFFF_F800_0000_1234, hooked_addr],
        }));
        sink.on_event(&hooked_event);

        // Scenario E: Legitimate JIT/unbacked caller with legitimate system DLL transition on stack
        let jit_addr = 0x0000_7FFF_8888_0000u64;
        let jit_event = Arc::new(Event::CorrelatedSyscall(CorrelatedSyscallEvent {
            pid,
            tid: 1005,
            timestamp: 1090,
            syscall_address: Some(0xFFFF_F800_BF84_A090),
            frames: vec![
                0xFFFF_F800_0000_1234,
                legit_addr, // top user frame is inside ntdll.dll
                jit_addr,   // caller frame is unbacked JIT
            ],
        }));
        sink.on_event(&jit_event);

        // Verify alerts in AlertManager
        let alerts = alert_manager().recent_alerts(10);
        assert!(alerts.iter().any(|a| a.title == "Direct System Call Evasion"));
        assert!(alerts.iter().any(|a| a.title == "Unbacked Memory Direct System Call"));
        assert!(alerts.iter().any(|a| a.title == "Tampered/Hooked Syscall in Non-Executable Section"));
        assert!(CONTEXT.get_process(pid).unwrap().is_pinned());
    }
}
