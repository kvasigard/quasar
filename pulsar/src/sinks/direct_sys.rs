use std::sync::Arc;
use parking_lot::Mutex;
use crate::helpers::symbol_resolver::SymbolResolver;
use crate::pipeline::event::{CorrelatedSyscallEvent, Event};
use crate::pipeline::Subscriber;

/// Detection sink identifying direct system calls and unbacked memory syscall stubs.
pub struct DirectSyscallSink {
    /// Shared Windows DbgHelp wrapper for translating memory pointers to module/symbol names.
    resolver: Arc<Mutex<SymbolResolver>>,
}

impl DirectSyscallSink {
    /// Creates a new `DirectSyscallSink` instance with a shared symbol resolver.
    pub fn new(resolver: Arc<Mutex<SymbolResolver>>) -> Self {
        Self { resolver }
    }

    /// Core heuristic analyzing the resolved call stack for Direct Syscall patterns.
    ///
    /// # Direct Syscall Detection Heuristic:
    /// In legitimate Windows applications, syscall transitions from User Mode to Kernel Mode
    /// pass through `ntdll.dll` (or `win32u.dll`).
    ///
    /// When an attacker executes Direct Syscalls (e.g. Hell's Gate, SysWhispers),
    /// the instruction pointer immediately preceding kernel transition originates from
    /// an unbacked memory stub or directly from non-system binaries.
    #[tracing::instrument(name = "analyze_direct_syscall", skip(self, event), level = "debug")]
    fn analyze_direct_syscall(&self, event: &CorrelatedSyscallEvent) {
        // In 64-bit Windows, User Space ends at 0x00007FFFFFFFFFFF.
        const USER_SPACE_MAX: u64 = 0x00007FFFFFFFFFFF;

        let first_user_frame = event.frames.iter().copied().find(|&frame| frame <= USER_SPACE_MAX);

        if let Some(user_ptr) = first_user_frame {
            let mut resolver = self.resolver.lock();

            if let Some(resolved) = resolver.resolve_address(event.pid, user_ptr) {
                let mod_name = resolved.module_name.to_lowercase();

                if mod_name.contains("ntdll") || mod_name.contains("win32u") {
                    if log::log_enabled!(log::Level::Trace) {
                        let sym = resolved.symbol_name.as_deref().unwrap_or("Unknown");
                        log::trace!(
                            target: "direct_sys",
                            "Syscall: PID {} TID {} {}:{}",
                            event.pid,
                            event.tid,
                            resolved.module_name,
                            sym
                        );
                    }
                } else {
                    // Suppress loud terminal warnings for now until FP heuristics are refined
                    let sym = resolved.symbol_name.as_deref().unwrap_or("Unknown");
                    log::debug!(
                        target: "direct_sys",
                        "Direct syscall candidate: PID {} TID {} Addr {:#x} Module {} Symbol {}",
                        event.pid,
                        event.tid,
                        user_ptr,
                        resolved.module_name,
                        sym
                    );
                }
            } else {
                // Suppress loud terminal warnings for now until FP heuristics are refined
                log::debug!(
                    target: "direct_sys",
                    "Unbacked memory direct syscall candidate: PID {} TID {} Addr {:#x}",
                    event.pid,
                    event.tid,
                    user_ptr
                );
            }
        } else if log::log_enabled!(log::Level::Trace) {
            log::trace!(
                target: "direct_sys",
                "Kernel-only syscall: PID {}",
                event.pid
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
