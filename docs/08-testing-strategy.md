# 08 — Testing Strategy & Verification Architecture

Writing tests for an endpoint security platform requires balancing two competing goals: ensuring total reliability against subtle attack patterns and memory bugs, while keeping the test suite fast and frictionless for day-to-day development without requiring live kernel driver elevation on every run.

```
                        Quasar EDR Test Architecture
 ┌────────────────────────────────────────────────────────────────────────┐
 │ 1. Helpers & Parsers Unit Tests (pulsar/src/helpers/)                  │
 │    • String decoding, PE export table lookup, and ETW stack pairing    │
 ├────────────────────────────────────────────────────────────────────────┤
 │ 2. Context Engine State Machines (pulsar/src/context/tests.rs)         │
 │    • PID recycling isolation, in-place mutability, GC & injection      │
 ├────────────────────────────────────────────────────────────────────────┤
 │ 3. Shared ABI Layout Tests (shared/src/ioctl.rs)                       │
 │    • #[repr(C)] memory alignments and IOCTL control codes              │
 ├────────────────────────────────────────────────────────────────────────┤
 │ 4. Synthetic Pipeline Replay Integration (pulsar/tests/pipeline_replay)│
 │    • Raw EventRecord -> IngressParser -> SystemContext -> Sinks Alerts │
 └────────────────────────────────────────────────────────────────────────┘
```

## Why We Avoid Mandatory Kernel Execution in Local Tests

Testing an EDR traditionally presents a dilemma. If your test suite requires installing a signed kernel driver and elevating to `PsProtectedSignerAntimalwareLight`, tests cannot run in standard Continuous Integration environments or on unprivileged developer laptops.

To solve this, Quasar decouples telemetry ingestion logic from physical OS sensor drivers. While the sensors (`sensors/etw` and `singularity`) are responsible for interacting with Windows and pulling raw bytes, all parsing, context updates, correlation, and detection logic operate on standard `EventRecord` structs.

This architectural separation allows us to construct **Synthetic Kernel Telemetry**—crafting exact byte payloads for process starts, module mappings, and stack walks—and feeding them through the engine in memory. Our entire test suite executes in under half a second with zero OS dependencies.

## The Four Testing Layers

### 1. Helper and Parser Unit Tests

Located directly in `pulsar/src/helpers/`, these unit tests verify defensive programming around untrusted binary buffers:
* In `helpers/strings.rs`, tests verify extraction of null-terminated UTF-16 strings, empty slices, odd byte lengths, and truncated ANSI strings.
* In `helpers/pe/tests.rs`, tests verify pure-Rust DOS/NT header parsing, 64-bit and 32-bit optional headers, live system DLL export extraction, and defensive rejection of corrupted buffers.
* In `helpers/stack_correlator.rs`, tests verify event pairing regardless of whether the system call trigger or the kernel stack walk arrives first, as well as ring-buffer capacity eviction when orphan events accumulate.

### 2. Context Engine State Machine Tests

Located in `pulsar/src/context/tests.rs`, these tests validate the core invariants of our operating system knowledge graph:
* **PID Recycling Isolation:** Confirms that when an operating system reuses a PID after a process terminates, the new process receives a distinct synthetic key, preserving historical forensics without data contamination.
* **Concurrent In-Place Mutability:** Spawns multiple concurrent threads recording module loads, open handles, and thread IDs against the same process context simultaneously, ensuring lock-free read access remains consistent.
* **Lineage Graph Walking:** Verifies that walking backward through parent synthetic keys traverses multi-generation process trees accurately.
* **Dual-Trigger Garbage Collection:** Validates that pinned processes are immune to eviction, expired processes with active children become tombstones, and unpinned standalone processes are purged once their retention window expires.
* **Stateful Injection Correlation:** Simulates the sequential progression of an in-memory injection (OpenProcess $\rightarrow$ VirtualAllocEx $\rightarrow$ WriteProcessMemory $\rightarrow$ Remote Execution Trigger) and verifies that confidence escalates to `Confirmed` while automatically pinning both processes.

### 3. Shared ABI & Memory Layout Tests

Located in `shared/src/ioctl.rs`, these tests safeguard the contract between user mode and kernel space. Because the KMDF driver and user-mode daemon share structs over raw memory pointers, any unintended compiler padding or alignment difference could cause kernel memory corruption. These tests assert exact byte sizes (`size_of::<ChangeProcessPplLevel>() == 8`) and 4-byte alignments at compile time.

### 4. End-to-End Synthetic Pipeline Replay Tests

Located in `pulsar/tests/pipeline_replay.rs`, this integration test exercises the full two-stage telemetry pipeline:
1. Spawns an `EventDispatcher` with a concurrent worker pool and registers our detection subscribers (`DirectSyscallSink`).
2. Transmits a synthetic raw `ProcessStart` event into the ingestion channel, verifying that `SystemContext` receives the metadata.
3. Transmits an evasive system call along with an unbacked user-mode return address on the stack walk.
4. Closes the channel and confirms that all events are correlated and delivered to the detection sinks cleanly before worker pool shutdown.

## How to Run and Author Tests

You can run the entire workspace test suite with a single Cargo command:

```powershell
cargo test --workspace
```

When authoring new detection sinks or context features:
1. If testing an isolated parsing or string conversion function, add a `#[cfg(test)]` module directly inside the source file.
2. If testing context relationships or state transitions, add a descriptive test function to `pulsar/src/context/tests.rs`.
3. If validating an end-to-end detection technique, add a synthetic replay scenario in `pulsar/tests/pipeline_replay.rs` that emits the required sequence of kernel records and asserts the expected sink alerts.
