# Kernel Driver Telemetry Sensors

Beyond user-mode ETW tracing, the Singularity KMDF driver (`singularity`) can register direct kernel notification callbacks. Kernel callbacks operate at the lowest level of the operating system, capturing events before user-mode code is executed.

```
 [Kernel Execution Point]
         │
         ▼
 [Singularity Driver Callbacks]
  • PsSetCreateProcessNotifyRoutineEx
  • PsSetCreateThreadNotifyRoutine
  • ObRegisterCallbacks (Handle Creation & Duplication)
         │
         ▼
 [Inverted Call / Shared Ring Buffer]
         │
         ▼
 [Pulsar Driver Sensor Thread]
         │
         ▼
 [Stage 1 Ingress Channel]
```

## Advantages of Kernel Driver Callbacks

While ETW is exceptional for high-volume tracing and stack walks, kernel driver callbacks provide capabilities that ETW cannot match:

Pre-execution visibility: With `PsSetCreateProcessNotifyRoutineEx`, the driver is notified of a new process while the process is still in its infancy (before the primary thread begins running user-mode instructions). The driver can inspect the binary path and command line arguments, and can even block execution by returning `STATUS_ACCESS_DENIED`.

Object handle filtering: With `ObRegisterCallbacks`, the driver intercepts handle creation and duplication requests targeting sensitive processes (such as `lsass.exe`), allowing the EDR to strip dangerous access masks (`PROCESS_VM_READ` or `PROCESS_TERMINATE`) before the handle is granted to the requesting process.

## How to Expand Driver Telemetry

To add a new driver callback sensor:
1. In `singularity/src/`, register the kernel notification callback during driver initialization (`DriverEntry`).
2. Write captured event structures to a circular buffer or an inverted-call IOCTL buffer.
3. In `pulsar/src/sensors/`, create a dedicated worker thread that consumes events from the driver IOCTL channel and pushes normalized `EventRecord` structs directly into the Stage 1 Ingress Channel.
