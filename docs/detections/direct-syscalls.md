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

To determine if a system call is legitimate or an evasive direct syscall, the sink applies a multi-layered evaluation pipeline:

### 1. User-Mode Caller Identification
On 64-bit Windows, user space is strictly confined to memory addresses below `0x00007FFFFFFFFFFF`. The sink filters through the return addresses on the stack to find the very first instruction pointer that falls within user space (`top_user_ptr`). This instruction pointer represents the exact code location that issued the `syscall` instruction or was returned to upon kernel transition.

### 2. In-Memory Module & PE Export Verification
Using Quasar's in-memory `ProcessContext` interval map (`find_module_by_address`) and `FileRegistry`'s cached `PeInfo` export tables (parsed by `helpers/pe/`):
* **Zero `dbghelp.dll` Lock Contention**: Rather than calling single-threaded Win32 debugging APIs under global mutexes, the sink performs sub-50ns in-memory interval queries.
* **Pure-Rust PE Export Verification**: If the instruction pointer resolves to a system DLL (such as `ntdll.dll` or `win32u.dll`), the sink queries `file_ctx.pe_info()` to verify that the return address corresponds to a recognized exported syscall stub (e.g. `NtAllocateVirtualMemory`, `NtProtectVirtualMemory`).

### 3. Microsoft OS & AppSDK Component Trust
Modern Windows desktop and UWP components (e.g. `Microsoft.ui.xaml.dll`, `StartMenuExperienceHost.exe`, `explorer.exe`, Windows App SDK packages located under `SystemApps`, `WinSxS`, or `WindowsApps`) legitimately execute system calls. The sink verifies their digital signature and system path classification, suppressing false alarms for verified Microsoft operating system modules.

### 4. Browser & Runtime JIT Engine Recognition
Web browsers and JavaScript/WebAssembly runtime hosts (`msedge.exe`, `msedgewebview2.exe`, `chrome.exe`, `brave.exe`, `node.exe`, `electron.exe`, etc.) compile code into dynamic, unbacked executable memory pages (`PAGE_EXECUTE_READWRITE` / `PAGE_EXECUTE_READ`).
* When an unbacked memory transition occurs inside a verified Microsoft or signed browser runtime, the sink classifies it as `[INFORMATIONAL] [Research] JIT Runtime Unbacked Memory System Call` (logged at `INFO` level without triggering SOC alerts).
* When an unbacked memory direct syscall occurs inside an arbitrary or unsigned binary (e.g. malware shellcode stubs like `SetThreadContext_Direct.exe`), it triggers **`[CRITICAL] [Defense Evasion] Unbacked Memory Direct System Call`** and pins the process.

### 5. Third-Party Signed Module Verification
Legitimate third-party applications (such as anti-cheat drivers, game engines, DirectX runtimes, and security agents like McAfee `libcurl.dll`) may execute direct system calls from on-disk binaries. 
* By resolving NT device paths (`\Device\HarddiskVolumeX`) to Win32 DOS drive letters (`C:\...`), `FileRegistry` verifies the Authenticode digital signature via `WinVerifyTrust`.
* Verified commercial third-party signatures are demoted to `[INFORMATIONAL] [Research]` telemetry, while unsigned binaries (such as indie game stubs like `Game.exe`) trigger **`[HIGH] [Defense Evasion] Direct System Call Evasion`**.

### 6. Alert Emission Policy (`OncePerProcess`)
To prevent alert fatigue and CPU exhaustion during high-frequency execution loops (such as games running at 60 FPS or browsers executing JIT code continuously), all direct syscall alerts are configured with `AlertEmissionPolicy::OncePerProcess`. The first occurrence per process lifecycle is captured and emitted, while repetitive subsequent events are deduplicated automatically in `AlertManager`.
