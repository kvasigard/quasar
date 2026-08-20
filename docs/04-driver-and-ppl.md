# 05 — Kernel Driver & PPL-Antimalware Elevation

The Singularity driver is Quasar's Kernel-Mode Driver Framework (KMDF) component. In version 0.2, its primary mission is establishing robust anti-tampering defenses by elevating the user-mode Pulsar daemon into a Protected Process Light (PPL-Antimalware) process.

```
 [Pulsar User-Mode Agent]
         │
         │ 1. Open handle to \\.\SingularityDevice via CreateFileW()
         │ 2. Send IOCTL_CHANGE_PROCESS_PPL with PID & Level (0x31)
         ▼
 [Singularity KMDF Driver]
         │
         │ 1. Lookup target PEPROCESS pointer (PsLookupProcessByProcessId)
         │ 2. RAII Guard manages object reference counting
         │ 3. DKOM: Volatile write to EPROCESS->Protection offset (0x5FA)
         ▼
 [Windows Kernel Security Manager]
         │
         │ Pulsar is now elevated to PPL-Antimalware
         │ Blocks PROCESS_TERMINATE & PROCESS_VM_WRITE even from Administrator
```

## Why Process Protection Light (PPL) is Essential for EDR

In an enterprise environment, advanced attackers frequently attempt to neutralize or blind endpoint detection agents as their very first action. If an attacker compromises an Administrator account or gains `NT AUTHORITY\SYSTEM` privileges, standard operating system security controls are no longer enough: an administrator can simply call `TerminateProcess`, attach a debugger to the EDR process, or inject a malicious thread to hook its telemetry collection functions.

Windows introduces Protected Process Light (PPL) specifically to defend critical antimalware software from these tampering attempts. When a process is running under `PPL-Antimalware`, the Windows kernel enforces strict access control checks on all process open requests. Even local Administrators and SYSTEM users are denied dangerous access rights, including:
* `PROCESS_TERMINATE` (prevents terminating the EDR agent)
* `PROCESS_VM_WRITE` and `PROCESS_VM_OPERATION` (prevents remote code injection and memory patching)
* `PROCESS_VM_READ` (prevents credential scraping and memory dumping)
* `PROCESS_SUSPEND_RESUME` (prevents freezing the agent's worker threads)

## Direct Kernel Object Manipulation (DKOM)

Under official Microsoft guidelines, starting a process natively under PPL requires an Early Launch Anti-Malware (ELAM) certificate signed directly by Microsoft. Standard developer builds and user-mode software cannot grant themselves PPL status through regular Win32 APIs.

To overcome this during active development and deployment, the Singularity driver performs Direct Kernel Object Manipulation (DKOM) inside `singularity/src/internals/dkom.rs`.

When Pulsar sends an elevation request, the driver resolves the internal kernel `PEPROCESS` structure for Pulsar's process ID using `PsLookupProcessByProcessId`. It then calculates the memory offset of the `Protection` byte within the `EPROCESS` structure (offset `0x5FA` on modern Windows 11 24H2 kernels) and executes a volatile write, setting the protection value to `0x31`. 

The value `0x31` represents `PROTECTION_LEVEL_ANTIMALWARE_LIGHT`, combining an Antimalware Signer tier (`0x3`) with a ProtectedLight Type tier (`0x1`). The moment this byte is written, the Windows kernel treats Pulsar as a fully protected antimalware service.

To ensure kernel memory safety, the `PEPROCESS` pointer is immediately wrapped in an RAII guard named `EprocessGuard`. When the guard goes out of scope, its `Drop` implementation automatically calls `ObDereferenceObject`, guaranteeing that kernel reference counts are always decremented properly and preventing kernel memory leaks.

## Type-Safe IOCTL Communication

Communication between user mode and kernel mode occurs over a standard Windows I/O Control (IOCTL) channel via the `\\.\SingularityDevice` device handle.

To prevent bugs, memory corruption, and ABI mismatches between user mode and kernel mode, all IOCTL codes and message structures are defined in the shared crate (`shared/src/ioctl.rs`) using the `IoctlMessage` trait. Both the user-mode client and the kernel driver import this single shared crate, ensuring that struct sizes, field alignments, and control codes match at compile time.

In user mode, sending a command is completely type-safe and requires no manual buffer calculations:

```rust
let kmdf_client = kmdf::Singularity::connect()?;
let request = ChangeProcessPplLevel {
    process_id: std::process::id(),
    level: 0x31,
};
kmdf_client.send(&request)?;
```

## Driver Expansion Notes

When you need to add new kernel driver capabilities or expand the communication channel, follow these steps:

To add a new IOCTL command, define the control code and the C-compatible request and response structs (`#[repr(C)]`) in `shared/src/ioctl.rs`. Implement the `IoctlMessage` trait for your request struct. In `singularity/src/device.rs`, add a new branch to the `EvtIoDeviceControl` dispatcher to handle the incoming request and write the response. In user mode, you can immediately send the new command via `Singularity::send(&command)` without writing any low-level FFI code.

When expanding kernel callbacks (such as intercepting process creation with `PsSetCreateProcessNotifyRoutineEx`), implement your logic in dedicated modules under `singularity/src/` and wrap all kernel pointers in custom RAII guards that handle cleanup on unregistration.
