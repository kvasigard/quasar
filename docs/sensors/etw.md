# NT Kernel Logger ETW Sensor

The NT Kernel Logger ETW Sensor in `pulsar/src/sensors/etw` is Quasar's primary telemetry provider in version 0.2. It configures the Windows kernel to trace process creation, module mapping, system call invocations, and kernel call stacks.

```
 [Windows NT Kernel Logger Provider]
         │
         │ Real-Time Ring Buffers (128 to 512 buffers of 1024 KB in Non-Paged Pool)
         ▼
 [KernelSession Real-Time Consumer]
         │
         │ ProcessTrace() blocking loop in dedicated OS thread
         ▼
 [etw_callback Function]
         │
         │ Non-blocking tx.try_send(record)
         ▼
 [Stage 1 Ingress Channel]
```

## Why Real-Time ETW Instead of API Polling

A naive way to monitor an endpoint is periodically calling APIs like `CreateToolhelp32Snapshot` or `EnumProcesses` on a timer (for example, every 500 milliseconds).

This approach suffers from a Time-of-Check to Time-of-Use (TOCTOU) vulnerability. Malware can spawn a child process, execute an in-memory injection, perform its objective, and terminate in under 50 milliseconds, completely evading any periodic polling loop. Furthermore, constantly taking full-system process snapshots consumes excessive CPU.

Event Tracing for Windows operates in real time at the kernel level. When a process starts, a thread transitions into a system call, or a DLL is mapped into memory, the Windows kernel fires an event with sub-millisecond latency. Subscribing to real-time ETW ensures Quasar captures ephemeral processes before they can terminate.

## Managing Kernel Ring Buffers and the Session Director

System call, process lifecycle, and filesystem I/O tracing generate immense amounts of telemetry, frequently reaching between 50,000 and 200,000 events per second during software compilation, application updates, or heavy disk I/O. If user-mode software does not allocate sufficient kernel buffers, the Windows kernel will run out of space and silently drop events, causing blind spots in security monitoring.

Quasar addresses this by configuring large, dedicated non-paged pool ring buffers:
* **Buffer Size**: Set to 1024 KB (1 MB) per buffer, allowing the kernel to write batches of telemetry efficiently without frequent page allocations.
* **Buffer Count**: Dynamically managed between 128 and 512 buffers (up to 512 MB memory pool capacity), reserving ample memory to absorb sudden micro-bursts of high filesystem and syscall activity without dropping trace buffers.
* **Flush Timer**: Configured to 1 second, guaranteeing that even during quiet periods with low event volume, telemetry is flushed to user mode within one second.

To keep the low-level Win32 structure initialization clean and maintainable, we use the Session Director pattern in `sensors/etw/director.rs`. The director provides pre-configured recipes (like `construct_edr_session`) that enable the required kernel flags (`EVENT_TRACE_FLAG_PROCESS`, `EVENT_TRACE_FLAG_IMAGE_LOAD`, `EVENT_TRACE_FLAG_DISK_FILE_IO`, `EVENT_TRACE_FLAG_FILE_IO_INIT`, `EVENT_TRACE_FLAG_SYSTEMCALL`, and StackWalk) on the session builder without cluttering main application logic with raw Windows FFI structs.

## Real-Time Consumption and Non-Blocking Ingestion

The consumer loop runs in a dedicated background thread named `pulsar-etw-consumer`. It opens the real-time trace using `OpenTraceW` with `PROCESS_TRACE_MODE_REAL_TIME` and `PROCESS_TRACE_MODE_EVENT_RECORD`, and blocks on the Windows `ProcessTrace` API.

Every time the Windows kernel delivers a batch of records, our callback function `etw_callback` unpacks the header, copies the user payload, and pushes it into the Crossbeam ingestion channel.

A critical design choice here is using non-blocking channel sends (`tx.try_send(record)`) rather than blocking sends. If the user-mode ingestion pipeline ever experiences a temporary backlog, a blocking send inside `etw_callback` would freeze the Windows kernel's trace delivery thread. Stalling the kernel delivery thread causes Windows to immediately overflow the non-paged pool buffers and drop all subsequent events across the entire operating system. Using `try_send` ensures that the kernel delivery loop is never blocked, preserving trace stability even during extreme loads.

## ETW Sensor Expansion Notes

When adding new ETW providers (such as the `Microsoft-Windows-Threat-Intelligence` provider or `Microsoft-Windows-PowerShell`), implement the `EtwSessionBuilder` trait in `sensors/etw/session.rs` for the new session. Add a recipe in `SessionDirector` that configures the provider GUID and enable flags using `EnableTraceEx2`. Connect the new session's consumer callback to the exact same Crossbeam channel (`Sender<EventRecord>`), allowing Stage 1 of the pipeline to route and correlate the new telemetry automatically.
