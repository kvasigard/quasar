# 01 — Architecture Overview & Future Vision

Quasar is built around a practical reality of modern endpoint security: to detect sophisticated attacks like process hollowing, token manipulation, or direct system calls, an agent needs visibility into both kernel-level events and rich historical context. However, doing this without slowing down the user's computer or consuming unreasonable amounts of memory requires a careful balance between low-level performance and high-level behavioral analysis.

To solve this challenge, Quasar is split into two distinct tiers: a lightweight kernel driver named Singularity, and a user-mode telemetry and detection daemon named Pulsar.

## The Two-Tier System

Singularity operates in kernel space as a Kernel-Mode Driver Framework (KMDF) component. Its primary job in version 0.2 is to provide tamper resistance by elevating the user-mode Pulsar daemon into a Protected Process Light (PPL-Antimalware) process. This ensures that even if an attacker acquires full local Administrator or SYSTEM privileges on the machine, they cannot terminate the Pulsar process, inject DLLs into its memory space, or suspend its threads.

Pulsar runs in user space as the central intelligence engine. It configures Event Tracing for Windows (ETW) to receive real-time streams of operating system activity, reconstructs the relationships between processes, files, and network connections in memory, and passes this data through analytical detection sinks to spot anomalous behavior.

```
 [Kernel Space: Singularity Driver]
         │
         │  1. Elevates Pulsar to PPL-Antimalware (Anti-Tamper)
         │  2. Future: Process, Thread & File Object Callbacks
         ▼
 [User Space: Pulsar Agent]
         │
         ├─► ETW Sensor Layer (NT Kernel Logger Real-Time Stream)
         │
         ├─► Ingress Pipeline (Validation, Deduplication & Stack Correlation)
         │
         ├─► System Context Graph (Live Knowledge Base of OS Activity)
         │
         └─► Multi-Threaded Dispatcher (Concurrent Detection Sinks)
```

## The Two-Stage Ingestion Model

A common pitfall in telemetry processing is letting every analytical rule parse raw binary kernel events directly. When multiple detection rules try to decode the same raw packet, they waste CPU cycles doing redundant work. Even worse, if different rules process events out of order, one rule might attempt to evaluate a child process before the process creation rule has had a chance to record the parent in the system graph, leading to false negatives and race conditions.

Quasar avoids this problem by using a two-stage pipeline.

In the first stage, a dedicated Ingress Parser serves as the single source of truth for all incoming telemetry. It inspects raw byte buffers from the kernel, checks boundaries to prevent memory errors, merges duplicate events that might arrive from multiple overlapping sensors, and correlates asynchronous system call triggers with their matching kernel call stacks. Most importantly, it updates the central System Context graph immediately and synchronously.

In the second stage, the fully parsed and enriched event is handed off to a multi-threaded Event Dispatcher. The dispatcher fans out the event across a pool of background worker threads where analytical sinks can evaluate rules concurrently. Because the System Context graph was already updated during the first stage, every sink is guaranteed to see a complete and accurate snapshot of system state without any race conditions.

## Vision for Future Expansion

The current architecture is intentionally structured as a modular foundation that will naturally evolve across upcoming releases.

On the telemetry collection side, the sensor subsystem is designed to accept multiple simultaneous data providers. While version 0.2 relies on the NT Kernel Logger ETW session, future iterations will seamlessly ingest events from the Microsoft-Windows-Threat-Intelligence provider (ETW-TI) to gain visibility into memory allocation APIs and direct kernel callbacks registered by the Singularity driver, such as process creation and object access routines. Because Stage 1 normalizes all incoming telemetry into standard domain events, adding new kernel sensors will require zero changes to existing detection sinks.

On the detection side, the dispatcher's subscriber model makes adding new behavioral analytics effortless. New sinks can be written for parent PID spoofing, LSASS memory dumping, ransomware encryption patterns, or network beaconing, simply by implementing a basic subscriber interface and attaching the sink to the dispatcher.

Finally, the System Context knowledge graph is designed to scale beyond a single machine. By assigning persistent, monotonic synthetic keys to every process and file rather than relying on recycled operating system identifiers, Quasar's in-memory graph can be serialized, streamed to central telemetry lakes, or queried by graph-based threat hunting tools for fleet-wide behavioral correlation.
