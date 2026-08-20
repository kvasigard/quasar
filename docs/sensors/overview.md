# Sensors Subsystem Overview

The sensors subsystem interfaces directly with the Windows operating system to collect raw kernel and user-mode events as they occur. Rather than polling APIs on recurring timers, Quasar relies on event-driven streaming sensors that capture ephemeral activity with sub-millisecond latency.

```
                  ┌────────────────────────────────────────┐
                  │           Sensors Subsystem            │
                  └───────────────────┬────────────────────┘
                                      │
            ┌─────────────────────────┴─────────────────────────┐
            ▼                                                   ▼
   NT Kernel Logger ETW                                Singularity Driver
   (Process, Image, Syscalls, Stacks)                  (PPL, Kernel Callbacks)
            │                                                   │
            └─────────────────────────┬─────────────────────────┘
                                      │ EventRecord
                                      ▼
                        Stage 1 Ingress Channel
```

## Available Sensors

* [NT Kernel Logger (ETW)](etw.md): Windows Event Tracing for high-volume system call, process creation, image load, and call stack telemetry.
* [Kernel Driver Callbacks](driver-sensor.md): Direct notification callbacks registered by the Singularity KMDF driver for process and thread creation.

## Design Philosophy

Sensors in Quasar have a single responsibility: capture low-level system activity and push raw `EventRecord` structs into the Stage 1 Ingress Channel without performing expensive parsing or blocking operations.

All sensors deliver data to the same centralized ingestion channel (`crossbeam_channel::Sender<EventRecord>`), allowing the Stage 1 Ingress Parser to normalize and correlate telemetry regardless of which sensor produced it.
