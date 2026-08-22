# 03 — Telemetry Ingress & Pipeline Dispatcher

The pipeline and dispatcher subsystem bridges low-level kernel sensor telemetry with high-level analytical detection sinks. It is responsible for taking raw, high-volume byte packets from the operating system, verifying their integrity, correlating related events, updating the global knowledge graph, and distributing the resulting domain events to analytical sinks across multiple worker threads.

```
 [Kernel Trace Stream]
         │
         ▼
 [Ingestion Channel: crossbeam_channel::bounded(1_000_000)]
         │
         ▼
 [Stage 1: IngressParser (Single Source of Truth)]
  • Verify payload lengths and unpack binary structures
  • Merge duplicate records from overlapping sensors
  • Correlate asynchronous SyscallEnter events with Stack_Walk call frames
  • Update SystemContext in-place before dispatching
         │
         ▼
 [Stage 2: EventDispatcher Multi-Threaded Worker Pool]
  • Lock-free MPMC work distribution across 1 to 4 worker threads
  • Fan-out strongly-typed Arc<Event> to registered analytical sinks
```

## Stage 1: Defensive Parsing and Stack Correlation

Telemetry from the kernel arrives as raw byte slices. To guarantee that a malformed packet or unexpected memory layout can never crash the agent, the Ingress Parser enforces strict compile-time minimum struct sizes on all incoming records before attempting to read their contents. If a packet is shorter than expected, it is safely rejected as a truncated payload rather than triggering an out-of-bounds memory panic.

Stage 1 also handles multi-source event deduplication. In a live system, telemetry about a process starting can arrive from multiple sources at roughly the same time, such as an initial ETW process rundown and a kernel driver callback. Instead of creating redundant process nodes in memory, the Ingress Parser checks if an active entry already exists for that process ID. If it does, it merges any enriched metadata (like command line arguments or package details) directly into the existing context in-place.

Another critical responsibility of Stage 1 is call stack correlation. When Windows traces system calls through ETW, it splits the information across two separate events: first, a `SyscallEnter` event fired directly on the CPU core when a thread issues a system call, and second, an asynchronous `Stack_Walk` event delivered a short time later by the kernel stack unwinder containing the array of return addresses. The `StackCorrelator` pairs these asynchronous events in a small, time-ordered ring buffer. By performing this correlation in Stage 1, all downstream detection sinks receive a unified event containing both the syscall details and its complete call stack without having to duplicate buffering logic in every sink.

## Asynchronous Metadata Enrichment Offloading

To ensure Stage 1 Ingress processing latency remains under 100 nanoseconds per event, heavy disk I/O and synchronous Win32 API calls (such as Authenticode signature verification via `WinVerifyTrust` or full PE header inspection) are strictly prohibited on the Ingress and Dispatcher worker threads.

When `IngressParser` processes a process creation or image load, `SystemContext::get_or_create_file` registers the image path in `FileRegistry` and dispatches an `EnrichmentTask::NewFile(FileKey)` to the background `pulsar-context-enrichment` worker via a non-blocking `.try_send()` channel handoff. This completely isolates the real-time kernel event pipeline from disk latency and OS certificate validation overhead.

## Stage 2: Concurrent Work Distribution with Crossbeam Channels

Once Stage 1 produces a strongly-typed domain event and updates the context, the event is wrapped in a shared pointer (`Arc<Event>`) and dispatched across the worker pool.

To distribute work efficiently across multiple threads without locking, Quasar uses `crossbeam-channel`. Standard library channels (`std::sync::mpsc`) only support a single receiver, which means you cannot have multiple worker threads pulling directly from the same channel without an extra multiplexer thread. Shared mutex queues (`Arc<Mutex<VecDeque<T>>>`) allow multiple workers, but every time a thread wants to pop an event, it blocks all other workers, creating severe lock contention during high-volume bursts.

Crossbeam channels solve this with a lock-free Multi-Producer Multi-Consumer (MPMC) design. Multiple dispatcher worker threads concurrently pop events from the same bounded queue using atomic operations. When there are no events in the queue, the worker threads are suspended in the operating system kernel at zero percent CPU usage, waking up within microseconds the moment a new packet is pushed. When the kernel sensor stops and closes the channel, all worker threads naturally drain any remaining events in the buffer and shut down cleanly.

## Why We Bound the Dispatcher Thread Pool

It is common in Rust applications to default worker thread counts to the total number of logical CPU cores on the host (`std::thread::available_parallelism()`). While this works well for CPU-bound computations, applying it blindly to an EDR agent can cause serious problems in production.

On a large server or cloud virtual machine with 64 or 128 cores, spawning 128 worker threads creates massive thread context switching and cache thrashing overhead. Furthermore, if an EDR consumes all available CPU cores during sudden event spikes, it can starve the customer's actual production workloads, triggering cloud monitoring alerts.

To prevent this, Quasar automatically clamps the dispatcher worker pool to between 1 and 4 threads:

```rust
let num_workers = thread::available_parallelism()
    .map(|n| n.get())
    .unwrap_or(2)
    .clamp(1, 4);
```

This ensures bounded, predictable CPU utilization while providing more than enough concurrent capacity to process hundreds of thousands of events per second.

## Pipeline Expansion Notes

When adding new event types or registering new analytical sinks, follow these practical steps:

To add a new domain event, define the event struct in the appropriate domain module in `pipeline/event/` (such as `process.rs`, `image.rs`, `file.rs`, or `syscall.rs`) and re-export it in `pipeline/event/mod.rs` as a new variant of the central `Event` enum. In `IngressParser::process_raw_record()`, match on the corresponding kernel provider GUID and opcode, invoke the dedicated handler in `context/handlers/`, and return your new event variant.

To create and attach a new detection sink, define a struct that implements the `Subscriber` trait in `pipeline/dispatcher.rs`. In `is_interested(&self, event: &Event)`, return `true` only for the event variants your sink cares about. In `on_event(&self, event: &Arc<Event>)`, write your detection logic. Finally, register the sink with the dispatcher in `main.rs` by calling `dispatcher.add_subscriber(Box::new(YourNewSink))`.
