# 02 — The System Context Knowledge Graph

At the core of Pulsar is the System Context Engine, an in-memory knowledge graph that maintains an up-to-the-millisecond picture of what is happening across the entire operating system. It tracks the full lineage of every running process, the dynamic link libraries loaded into virtual memory, open kernel handles, security tokens, touched files, active network sockets, and interactions between different processes.

When a detection rule wants to know whether a system call is legitimate, it does not just look at the event in isolation. It asks the System Context questions like: Who is the parent of this process? Did this process recently allocate executable memory inside a remote process? Has this process loaded unusual DLLs? The context engine makes these queries fast and reliable.

```
                      ┌────────────────────────────────────────┐
                      │      SystemContext Central Facade      │
                      └───────────────────┬────────────────────┘
                                          │
        ┌───────────────────┬─────────────┴───────┬───────────────────┐
        ▼                   ▼                     ▼                   ▼
  ProcessTree          FileRegistry        NetworkRegistry   InteractionRegistry
(DashMap Shards)    (Path Normalization)   (Socket Tracking) (Cross-Process Memory)
        │
        ▼
 RetentionManager (Dual-Trigger GC: Time TTL + Capacity LRU + Ancestry Tombstones)
```

## Why We Use Synthetic Keys Instead of Operating System PIDs

One of the most dangerous traps when building an endpoint detection engine is trusting operating system Process IDs as unique identifiers. Windows reuses PIDs aggressively. If a short-lived process with PID 4500 starts and exits, the operating system might assign that same PID 4500 to a completely unrelated application just a few milliseconds later.

If an EDR uses raw PIDs as primary keys, telemetry from the new application can easily contaminate the historical records of the old process. Worse, if a delayed telemetry event arrives slightly out of order, detection rules could attribute malicious actions performed by the old process to the innocent new process.

To eliminate this problem completely, Quasar assigns a 64-bit monotonic synthetic key to every entity, such as `ProcessKey`, `FileKey`, `ThreadKey`, and `ConnectionKey`. These numbers are generated from a global atomic counter that increments continuously and never wraps around. 

When a process with PID 4500 starts, it receives a brand new synthetic key (for example, key #1024). When it exits, PID 4500 is immediately unmapped from the active routing table, but all historical data remains safely indexed under key #1024. If Windows recycles PID 4500 for a new process a moment later, that new process receives key #1025. The two processes remain strictly separated in memory, guaranteeing total temporal isolation.

## In-Place Mutability and Memory Efficiency

A running process is constantly changing: it starts new worker threads, opens file handles, maps DLLs, and opens network sockets. In a naive immutable data structure, modifying a process requires cloning the entire process object and updating a global map. For a busy process like a web browser or developer IDE that loads dozens of DLLs and opens thousands of handles, constantly cloning objects causes heavy heap allocations and memory fragmentation.

Instead, Quasar uses a pattern called fine-grained interior mutability. The outer `ProcessContext` struct is immutable and wrapped in a reference counter (`Arc<ProcessContext>`), meaning references to it can be shared freely across worker threads. Inside the struct, individual sub-tables (like the map of loaded modules, open handles, or touched files) are protected by small, lightweight `parking_lot::RwLock` locks.

We chose `parking_lot::RwLock` over the standard library's `std::sync::RwLock` because it is significantly smaller (only 1 byte of overhead instead of 24 bytes), does not poison on panics, and uses fast user-space spinning before parking threads in the kernel, making read and write operations practically instantaneous. Furthermore, frequent status checks (such as whether a process is alive, pinned, or marked as a tombstone) are stored as atomic booleans (`AtomicBool`), allowing detection threads to check process state without acquiring any locks at all.

## How Registries Manage Concurrency with DashMap

The central context is composed of specialized registries for processes, files, network connections, and cross-process interactions.

A classic bottleneck in concurrent Rust applications is wrapping an entire collection in a single global lock (like `Arc<RwLock<HashMap<K, V>>>`). When dozens of worker threads and ingestion handlers are receiving high volumes of telemetry simultaneously, every thread ends up waiting in line for that single global lock, bringing throughput to a crawl.

To avoid this, Quasar uses `DashMap` for its primary registry tables. `DashMap` divides the hash table into multiple independent shards (typically 64 shards on modern multi-core processors), each with its own internal lock. When Thread 1 is inserting a new process into Shard 4, Thread 2 can read a file from Shard 12 at the exact same time without any contention. This lock-striping design allows Quasar to scale smoothly across multiple CPU cores under heavy event storms.

In the case of `InteractionRegistry`, which tracks cross-process activities like remote memory writes and handle duplications, we combine a `VecDeque` ring buffer with secondary `DashMap` indices. The ring buffer enforces a hard limit on total memory (for example, storing the last 100,000 interactions), automatically dropping the oldest records when full, while the secondary indices allow instant lookups for queries like "what processes interacted with LSASS?" without scanning the entire history.

## Dual-Trigger Garbage Collection and Ancestry Tombstones

Because an endpoint agent runs continuously for weeks or months, it cannot keep every terminated process in memory forever. The `RetentionManager` periodically performs garbage collection to reclaim memory using a dual-trigger strategy: it evaluates both a time-to-live threshold (such as keeping terminated processes for 10 minutes) and a maximum capacity limit (such as keeping at most 50,000 process nodes).

However, simply deleting old processes creates a serious problem for security analysis: if a parent process spawns a malicious child and then terminates quickly, deleting the parent would break the ancestry chain, leaving the child as an orphan and blinding detection rules that inspect parent-child relationships.

Quasar solves this by applying three retention rules:

First, any process that triggered a detection alert or exhibited suspicious behavior is flagged as pinned (`is_pinned == true`). Pinned processes are permanently exempt from garbage collection so their full forensic history is preserved for incident response.

Second, if an unpinned process expires but still has active child processes running on the system, the garbage collector does not delete it. Instead, it converts the process into an Ancestry Tombstone. The heavy sub-tables (such as open handles, loaded modules, and file lists) are deallocated to free up memory, but the node's identity and lineage links are preserved. This ensures that child processes can always walk their ancestry chain backwards to find their true origin.

Third, when a process has terminated, is not pinned, and has no living descendants, it is permanently removed from memory.

## In-Memory Loaded Module Interval Map & Fast Address Resolution

Detection sinks (such as Direct System Call detectors) frequently need to resolve the originating binary or DLL of return addresses in real time. Calling external symbol resolution engines (like Windows `DbgHelp`) during high-frequency system calls causes severe lock contention, single-threaded bottlenecks, and disk I/O latency.

To eliminate this overhead, `ProcessContext` maintains an in-memory interval array of loaded binary modules (`RwLock<Vec<LoadedModule>>`), populated directly from ETW `ImageLoad` and `ImageUnload` events:
- **Sorted Contiguous Storage**: Module entries are kept sorted by `base_address` in contiguous memory, enabling CPU cache-friendly $O(\log N)$ binary search without heap pointer hopping.
- **Half-Open Range Resolution**: Address resolution queries test the interval `[base_address, base_address + image_size)` using saturating arithmetic to prevent integer overflow.
- **Centralized `FileRegistry` Linkage**: Each mapped image record stores an optional `FileKey` referencing its canonical `FileContext` in the central `FileRegistry`.
- **System Binary Classification**: Modules located under recognized Windows system directories (such as `\System32\` or `\SysWOW64\`) are classified with the `is_system` flag for fast anomaly filtering.
- **Sub-50ns Execution**: Lookups execute purely in-memory under lightweight `parking_lot::RwLock` read guards in less than 50 nanoseconds, without issuing Win32 debug or disk API calls.

## Context System Expansion Notes

When you want to expand the System Context with new capabilities, keep the following guidelines in mind to preserve performance and thread safety:

If you are adding a new entity type, such as a registry key context or a named pipe context, start by defining a dedicated monotonic key in `identity.rs` (for example, `pub struct RegistryKey(pub u64)`). Then create your model in `models/` using `parking_lot::RwLock` for sub-collections and atomics for timestamps and status flags. Store the entities inside a dedicated registry in `registries/` using `DashMap` for lock-striped concurrency, and make sure your container exposes standard `len()` and `is_empty()` methods. Finally, expose clean query methods on the main `SystemContext` facade.

If you are adding a new interaction kind (such as named pipe impersonation or token duplication), add the new variant to the `InteractionKind` enum in `models/interaction.rs`. Record the interaction through `ctx.record_interaction()`, and if the action represents confirmed malicious behavior, be sure to call `.pin()` on the participating process contexts so the garbage collector preserves their forensic history.
