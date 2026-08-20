# Quasar EDR Documentation (v0.2)

Welcome to the technical documentation for Quasar EDR. This guide covers both the user-mode agent (Pulsar v0.2) and the kernel-mode driver (Singularity v0.1), walking you through how the system works, the reasoning behind our design choices, and how the codebase can be smoothly expanded over time.

Whether you are a developer looking to write new detections, an engineer maintaining driver communications, or someone curious about how modern endpoint telemetry works under the hood, these documents are written to be accessible and straightforward without requiring deep expertise in Windows internals or advanced Rust.

```
                              Windows Operating System
                                   │
                 ┌─────────────────┴─────────────────┐
                 ▼                                   ▼
        Singularity Driver                  NT Kernel Logger
       (KMDF Kernel Driver)                  (Real-Time ETW)
                 │                                   │
                 │ IOCTL Channel                     │ Raw Event Stream
                 ▼                                   ▼
  ┌────────────────────────────────────────────────────────────────────────┐
  │                     Pulsar User-Mode Agent (v0.2)                      │
  │                                                                        │
  │  1. Ingress Channel (crossbeam_channel bounded buffer)                 │
  │  2. Stage 1 Ingress Parser (Parsing, Deduplication & Stack Correlation)│
  │  3. SystemContext Knowledge Graph (Processes, Files, Network & Memory) │
  │  4. Stage 2 Multi-Threaded Dispatcher (Concurrent Analytical Sinks)   │
  └────────────────────────────────────────────────────────────────────────┘
```

## Documentation Roadmap

1. [Architecture Overview](01-architecture-overview.md): High-level system structure, the two-stage telemetry model, and how the platform is designed to scale and grow in future versions.
2. [The System Context Engine](02-context-engine.md): The real-time knowledge graph tracking processes, files, network connections, and code injections, along with our approach to identity, mutability, and garbage collection.
3. [Telemetry Ingress & Pipeline Dispatcher](03-pipeline-and-dispatcher.md): How raw kernel records are validated, correlated with call stacks, and distributed across a concurrent worker pool.
4. [Sensors Subsystem](sensors/overview.md):
   * [NT Kernel Logger (ETW)](sensors/etw.md): Real-time ETW trace sessions, kernel ring buffers, and non-blocking ingestion.
   * [Kernel Driver Callbacks](sensors/driver-sensor.md): Direct kernel notification callbacks and future sensor capabilities.
5. [Kernel Driver & PPL Elevation](04-driver-and-ppl.md): How the Singularity KMDF driver communicates with user mode and uses Direct Kernel Object Manipulation to establish Protected Process Light defenses.
6. [Bootstrap, Lifecycle & Teardown](05-bootstrap-and-lifecycle.md): Pre-flight privilege checks, driver installation into the Windows Driver Store, service management, and zero-CPU shutdown mechanics.
7. [Detection Sinks](detections/overview.md):
   * [Direct System Calls](detections/direct-syscalls.md): Detecting user-mode hook bypasses via return address filtering and PE export parsing.
   * [Stateful Code Injection Correlator](detections/injection-correlator.md): Multi-step behavioral correlation across memory allocations, writes, and remote execution.
8. [Error Handling Architecture](06-error-taxonomy.md): Our domain-partitioned error taxonomy, how errors bubble up cleanly across subsystems, and how to add new error variants.
9. [Structured Tracing & Profiling](07-tracing-and-profiling.md): Measuring execution timing with spans, isolating bottlenecks, and exporting interactive flame charts for Chrome and Perfetto.
10. [Testing Strategy & Verification](08-testing-strategy.md): The four-layer testing architecture, unit testing vs synthetic replay, and guidelines for authoring new tests.
11. [System Expansion Notes](09-system-expansion-notes.md): General guidelines, coding conventions, and architectural best practices to keep the project clean and maintainable.
