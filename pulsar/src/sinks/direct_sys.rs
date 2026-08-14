//! Direct Syscall detection sink utilizing ETW stack trace correlation.

use crate::helpers::stack_correlator::{StackCorrelator, StackWalkPayload};
use crate::helpers::symbol_resolver::SymbolResolver;
use crate::pipeline::{Event, Subscriber};
use std::sync::{Arc, Mutex};

/// Detection sink that detects direct system calls and unbacked memory syscall executions.
pub struct DirectSyscallSink {
    /// Matches `Stack_Walk` events with their trigger events.
    correlator: Mutex<StackCorrelator>,
    /// Shared Windows DbgHelp wrapper for translating memory pointers to module/symbol names.
    resolver: Arc<Mutex<SymbolResolver>>,
}

impl DirectSyscallSink {
    /// Creates a new `DirectSyscallSink` instance with a shared symbol resolver.
    ///
    /// # Arguments
    ///
    /// * `resolver` - Shared, thread-safe reference to the `SymbolResolver`.
    ///
    /// # Returns
    ///
    /// An initialized `DirectSyscallSink`.
    pub fn new(resolver: Arc<Mutex<SymbolResolver>>) -> Self {
        Self {
            // Initialize correlator with a limit to avoid unbounded memory growth
            // from orphaned events or stacks.
            correlator: Mutex::new(StackCorrelator::new(10_000)),
            resolver,
        }
    }

    /// Core logic to analyze the resolved call stack for Direct Syscall patterns.
    ///
    /// # Direct Syscall Detection Heuristic
    /// When a legitimate Windows application performs a syscall, the execution flow
    /// transitions from User Mode to Kernel Mode through `ntdll.dll` (or `win32u.dll`).
    ///
    /// If an attacker uses Direct Syscalls, they execute the `syscall` assembly
    /// instruction directly from their own executable or an allocated memory stub.
    ///
    /// # Arguments
    ///
    /// * `_original_event` - Shared reference to the triggering syscall event.
    /// * `stack` - Correlated stack walk payload containing instruction pointer frames.
    fn analyze_direct_syscall(&self, _original_event: Arc<Event>, stack: StackWalkPayload) {
        // In 64-bit Windows, User Space ends at 0x00007FFFFFFFFFFF.
        const USER_SPACE_MAX: u64 = 0x00007FFFFFFFFFFF;

        let mut first_user_frame: Option<u64> = None;
        for frame in &stack.frames {
            if *frame <= USER_SPACE_MAX {
                first_user_frame = Some(*frame);
                break;
            }
        }

        if let Some(user_ptr) = first_user_frame {
            let mut resolver = self.resolver.lock().unwrap();

            if let Some(resolved) = resolver.resolve_address(stack.stack_process, user_ptr) {
                let mod_name = resolved.module_name.to_lowercase();

                if mod_name.contains("ntdll") || mod_name.contains("win32u") {
                    if log::log_enabled!(log::Level::Trace) {
                        let sym = resolved.symbol_name.as_deref().unwrap_or("Unknown");
                        log::trace!(
                            target: "direct_sys",
                            "Syscall: PID {} TID {} {}:{}",
                            stack.stack_process,
                            stack.stack_thread,
                            resolved.module_name,
                            sym
                        );
                    }
                } else {
                    let sym = resolved.symbol_name.as_deref().unwrap_or("Unknown");
                    log::debug!(
                        target: "direct_sys",
                        "Direct syscall: PID {} TID {} Addr {:#x} Module {} Symbol {}",
                        stack.stack_process,
                        stack.stack_thread,
                        user_ptr,
                        resolved.module_name,
                        sym
                    );
                }
            } else {
                log::debug!(
                    target: "direct_sys",
                    "Unbacked syscall: PID {} TID {} Addr {:#x}",
                    stack.stack_process,
                    stack.stack_thread,
                    user_ptr
                );
            }
        } else if log::log_enabled!(log::Level::Trace) {
            log::trace!(
                target: "direct_sys",
                "Kernel-only syscall: PID {}",
                stack.stack_process
            );
        }
    }
}

impl Subscriber for DirectSyscallSink {
    /// Implements the Level 2 filter so the Dispatcher only sends relevant events.
    ///
    /// # Arguments
    ///
    /// * `event` - The pipeline event to check.
    ///
    /// # Returns
    ///
    /// `true` if the event is a stack walk or syscall enter record.
    fn is_interested(&self, event: &Event) -> bool {
        let Event::Etw(record) = event;

        // STACKWALK_GUID: DEF2FE46-7BD6-4B80-BD94-F57FE20D0CE3 (Opcode 32)
        let is_stackwalk = record.opcode == 32 && record.provider_id.data1 == 0xdef2fe46;

        // PERFINFO_GUID: CE1DBFB4-39EA-4851-89E0-A77CBFCCE4ED (Opcode 51 for SyscallEnter)
        let is_syscall = record.opcode == 51 && record.provider_id.data1 == 0xce1dbfb4;

        is_stackwalk || is_syscall
    }

    /// Receives and processes events approved by `is_interested`.
    ///
    /// # Arguments
    ///
    /// * `event` - Shared pointer to the incoming `Event`.
    fn on_event(&self, event: &Arc<Event>) {
        let Event::Etw(record) = &**event;

        let mut correlator = self.correlator.lock().unwrap();

        if let Some((orig_event, stack_payload)) = correlator.process_event(event, record) {
            self.analyze_direct_syscall(orig_event, stack_payload);
        }
    }
}
