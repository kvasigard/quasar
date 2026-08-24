# Direct System Calls Detection

The Direct Syscall Sink in `pulsar/src/sinks/direct_sys.rs` inspects system call invocations to detect user-mode evasion techniques.

```
 Legitimate System Call Path:
 [Application] ──► [ntdll.dll (Standard API)] ──► [syscall opcode] ──► [Windows Kernel]

 Direct Syscall Evasion Path:
 [Malware] ──────► [Custom Assembly Stub]   ──► [syscall opcode] ──► [Windows Kernel]
                   (Bypasses user-mode API hooks entirely)
```

## Why Attackers Use Direct Syscalls

Traditional security tools monitor Windows API activity by placing inline hooks (such as `JMP` instructions) inside `ntdll.dll`. When an application calls a function like `NtAllocateVirtualMemory`, execution jumps to the security tool's hook for inspection before continuing to the kernel.

Modern evasion frameworks (such as SysWhispers, Hell's Gate, Halo's Gate, and Tartarus' Gate) bypass these inline hooks entirely. Instead of calling `ntdll.dll`, the malware embeds its own assembly code stubs directly in memory, loading the system call number into the `EAX` register and executing the `syscall` instruction directly from its own binary or unbacked memory.

## How Quasar Detects Direct Syscalls

When the Windows kernel executes a system call, our ETW sensor captures the full kernel call stack—an array of return addresses (instruction pointers) left on the stack.

To determine if a system call is legitimate or an evasive direct syscall, the sink applies a two-step analysis:

First, it locates the user-mode caller. On 64-bit Windows, user space is strictly confined to memory addresses below `0x00007FFFFFFFFFFF`. The sink filters through the return addresses on the stack to find the very first instruction pointer that falls within user space. This instruction pointer represents the exact code location that issued the `syscall` instruction.

Second, it evaluates the instruction pointer using Quasar's in-memory `ProcessContext` interval map (`find_module_by_address`) and `FileRegistry`'s cached `PeInfo` export tables (parsed by `helpers/pe/`):
* **Zero `dbghelp.dll` Lock Contention**: Rather than calling single-threaded Win32 debugging APIs under global mutexes, the sink performs sub-50ns in-memory interval queries.
* **Pure-Rust PE Export Verification**: If the instruction pointer resolves to a system DLL (such as `ntdll.dll` or `win32u.dll`), the sink queries `file_ctx.pe_info()` to verify that the return address corresponds to a recognized exported syscall stub (e.g. `NtAllocateVirtualMemory`, `NtProtectVirtualMemory`).

If the instruction pointer falls in an unbacked memory region (such as dynamic heap memory or shellcode buffers not mapped from any file on disk), an anomaly alert is raised immediately because legitimate code does not execute system calls from unbacked memory.

If the instruction pointer resides inside an on-disk binary, the sink checks which module owns it. On Windows, legitimate user-mode system calls are designed to originate exclusively from system libraries like `ntdll.dll` (for core OS services) or `win32u.dll` / `user32.dll` (for graphics and UI services). If a system call originates directly from a third-party executable or an unexpected DLL, the sink immediately flags it as a Direct Syscall attack.
