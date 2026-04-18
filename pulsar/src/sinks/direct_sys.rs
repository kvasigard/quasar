use crate::helpers::stack_correlator::{StackCorrelator, StackWalkPayload};
use crate::helpers::symbol_resolver::SymbolResolver;
use crate::pipeline::{Event, Subscriber};
use std::sync::{Arc, Mutex};

pub struct DirectSyscallSink {
    /// Matches Stack_Walk events with their trigger events.
    correlator: Mutex<StackCorrelator>,
    /// Shared Windows DbgHelp wrapper for translating pointers to function names.
    resolver: Arc<Mutex<SymbolResolver>>,
}

impl DirectSyscallSink {
    pub fn new(resolver: Arc<Mutex<SymbolResolver>>) -> Self {
        Self {
            // Initialize correlator with a limit to avoid unbounded memory growth
            // from orphaned events or stacks.
            correlator: Mutex::new(StackCorrelator::new(10_000)),
            resolver,
        }
    }

    /// Core logic to analyze the resolved stack trace for Direct Syscall patterns.
    ///
    /// # Direct Syscall Detection Heuristic
    /// When a legitimate Windows application performs a syscall, the execution flow
    /// transitions from User Mode to Kernel Mode through `ntdll.dll` (or `win32u.dll`).
    ///
    /// Therefore, the stack trace should look like this:
    /// 1. ntoskrnl.exe (Kernel)
    /// 2. ...
    /// 3. ntdll.dll!NtReadVirtualMemory (First User-Mode frame)
    /// 4. kernelbase.dll
    /// 5. myapp.exe
    ///
    /// If an attacker uses Direct Syscalls, they execute the `syscall` assembly
    /// instruction directly from their own executable or an allocated memory stub.
    /// The resulting stack trace will lack `ntdll.dll` at the transition boundary:
    /// 1. ntoskrnl.exe (Kernel)
    /// 2. ...
    /// 3. malware.exe+0x1000 (First User-Mode frame - SUSPICIOUS!)
    fn analyze_direct_syscall(&self, original_event: Arc<Event>, stack: StackWalkPayload) {
        #[allow(irrefutable_let_patterns)]
        if let Event::Etw(_trigger_record) = &*original_event {
            // In 64-bit Windows, User Space ends at 0x00007FFFFFFFFFFF.
            // Anything above this is Kernel Space.
            const USER_SPACE_MAX: u64 = 0x00007FFFFFFFFFFF;

            // We walk the stack looking for the first frame that is in User Space.
            let mut first_user_frame: Option<u64> = None;

            for frame in &stack.frames {
                if *frame <= USER_SPACE_MAX {
                    first_user_frame = Some(*frame);
                    break;
                }
            }

            //  Analyze the transition point.
            if let Some(user_ptr) = first_user_frame {
                // Lock the shared resolver to perform the DbgHelp query safely.
                let mut resolver = self.resolver.lock().unwrap();

                if let Some(resolved) = resolver.resolve_address(stack.stack_process, user_ptr) {
                    let sym = resolved
                        .symbol_name
                        .unwrap_or_else(|| "UnknownFunction".to_string());
                    let mod_name = resolved.module_name.to_lowercase();

                    // Legitimate syscalls must originate from the Windows Native API (ntdll)
                    // or the Win32 GUI subsystem (win32u).
                    if mod_name.contains("ntdll") || mod_name.contains("win32u") {
                        // It is a normal, healthy OS operation.
                        log::trace!(
                            "[LEGIT SYSCALL] PID: {} | TID: {} | {}:{}",
                            stack.stack_process,
                            stack.stack_thread,
                            resolved.module_name,
                            sym
                        );
                    } else {
                        // A syscall was made directly from an executable or a random DLL.
                        // This is the defining signature of a Direct Syscall.
                        log::warn!(
                            "[MALWARE ALERT - DIRECT SYSCALL] PID: {} | TID: {} | Addr: {:#x} | Module: {} | Symbol: {}",
                            stack.stack_process,
                            stack.stack_thread,
                            user_ptr,
                            resolved.module_name,
                            sym
                        );
                    }
                } else {
                    // DbgHelp couldn't map the address to a file on disk.
                    // This often means the syscall originated from dynamically allocated memory,
                    // which is highly indicative of injected shellcode.
                    log::warn!(
                        "[MALWARE ALERT - UNBACKED MEMORY SYSCALL] PID: {} | TID: {} | Addr: {:#x} | No matching module!",
                        stack.stack_process,
                        stack.stack_thread,
                        user_ptr
                    );
                }
            } else {
                log::debug!(
                    "[SYSCALL] PID: {} | All frames in Kernel Space (System thread?)",
                    stack.stack_process
                );
            }
        }
    }
}

impl Subscriber for DirectSyscallSink {
    /// Implements the Level 2 filter so the Dispatcher only sends relevant events.
    #[allow(irrefutable_let_patterns)]
    fn is_interested(&self, event: &Event) -> bool {
        if let Event::Etw(record) = event {
            // STACKWALK_GUID: DEF2FE46-7BD6-4B80-BD94-F57FE20D0CE3 (Opcode 32)
            let is_stackwalk = record.opcode == 32 && record.provider_id.data1 == 0xdef2fe46;

            // PERFINFO_GUID: CE1DBFB4-39EA-4851-89E0-A77CBFCCE4ED (Opcode 51 for SyscallEnter)
            let is_syscall = record.opcode == 51 && record.provider_id.data1 == 0xce1dbfb4;

            return is_stackwalk || is_syscall;
        }
        false
    }

    /// Receives ONLY the events approved by `is_interested`.
    #[allow(irrefutable_let_patterns)]
    fn on_event(&self, event: &Arc<Event>) {
        if let Event::Etw(record) = &**event {
            // Lock the state machine to process the event
            let mut correlator = self.correlator.lock().unwrap();

            // The StackCorrelator attempts to match triggers (Syscalls) with their Stacks.
            // It returns Some(..) only when a perfect pair is formed based on PID, TID and EventTimeStamp.
            if let Some((orig_event, stack_payload)) = correlator.process_event(event, record) {
                self.analyze_direct_syscall(orig_event, stack_payload);
            }
        }
    }
}
