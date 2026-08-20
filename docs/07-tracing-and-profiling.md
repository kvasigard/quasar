# 07 — Structured Tracing & Profiling

Understanding where time is spent in a high-throughput endpoint agent is critical. When processing tens of thousands of system events per second, an unexpected lock contention or an unoptimized string lookup can introduce microsecond delays that quickly cascade into dropped kernel buffers.

To provide deep visibility into execution timing without adding runtime overhead in production, Quasar integrates the Tokio `tracing` framework in `pulsar/src/profiling.rs`.

Unlike traditional logging frameworks that only print flat, isolated text lines, `tracing` introduces structured Spans. A span represents a period of execution time with an explicit beginning and end. Spans can be nested hierarchically, tracking function entry parameters, internal child operations, and the exact number of microseconds taken from start to finish.

```
 [Worker Thread 1]
  └─ SPAN: ingress_process_record (took 3.8µs)
      ├─ SPAN: handle_process_start (took 1.2µs)
      │   └─ SPAN: insert_process (took 0.4µs)
      └─ SPAN: dispatch_event (took 2.1µs)
          └─ SPAN: analyze_direct_syscall (took 1.8µs)
```

## Instrumenting Code with `#[instrument]`

Adding timing and diagnostics to any function in Quasar is as simple as adding the `#[instrument]` attribute:

```rust
#[tracing::instrument(name = "ingress_process_record", skip(self, record), level = "debug", fields(pid = record.process_id, opcode = record.opcode))]
pub fn process_raw_record(&self, record: EventRecord) -> Option<Event> {
    // Function body execution time is automatically measured
}
```

When tracing is active, the function records its start time, execution duration, and context fields (like process ID and opcode). When tracing is disabled or running at a higher log level, these annotations compile down to simple atomic checks that execute in under two nanoseconds, adding virtually zero overhead in production.

## Exporting Interactive Flame Charts

While terminal logs are helpful for quick debugging, diagnosing complex multi-threaded concurrency issues is much easier with visual tools.

Quasar supports exporting complete execution traces into the standard Chrome DevTools and Perfetto format using the `--profile` command-line argument:

```powershell
cargo run -p pulsar --release -- --skip-driver --profile pulsar-trace.json
```

When this flag is passed, the profiling subsystem records every span and event across all worker threads into a compact JSON file. When you stop the agent with `Ctrl+C`, the `ProfilingGuard` safely flushes the recorded trace to disk.

## How to Isolate Bottlenecks in Chrome and Perfetto

To inspect your recorded trace:
1. Open Google Chrome or Microsoft Edge and navigate to `chrome://tracing`, or open any modern web browser and navigate to `https://ui.perfetto.dev`.
2. Drag and drop your `pulsar-trace.json` file directly into the browser window.

The browser renders an interactive, multi-threaded Flame Chart showing every worker thread on its own timeline:

```
 Perfetto / Chrome Trace Visualization:
 ─────────────────────────────────────────────────────────────────────────────
 Thread 1: [─── ingress_process_record ───] [─── dispatch_event ───]
             ├── handle_process_start ──┤     ├── analyze_direct_syscall ──┤
 ─────────────────────────────────────────────────────────────────────────────
 Thread 2: [─── ingress_process_record ───] [─── dispatch_event ───]
 ─────────────────────────────────────────────────────────────────────────────
```

## Statistical Queries in Perfetto SQL

Perfetto includes a built-in SQL query engine that allows you to calculate exact aggregate latencies and thread balancing distributions. Click on the "Query (SQL)" tab on the left sidebar to run analytical queries.

To compute the invocation counts, minimum, average, and maximum latencies, and total CPU time for every handler and detection sink, run:

```sql
SELECT 
  name AS operation,
  COUNT(*) AS invocations,
  ROUND(AVG(dur) / 1000.0, 2) AS avg_latency_us,
  ROUND(MIN(dur) / 1000.0, 2) AS min_latency_us,
  ROUND(MAX(dur) / 1000.0, 2) AS max_latency_us,
  ROUND(SUM(dur) / 1000000.0, 2) AS total_cpu_time_ms
FROM slice
GROUP BY name
ORDER BY total_cpu_time_ms DESC;
```

To verify how evenly events are being distributed across your worker thread pool, run:

```sql
SELECT 
  thread.name AS thread_name,
  COUNT(*) AS events_handled,
  ROUND(SUM(slice.dur) / 1000000.0, 2) AS active_time_ms
FROM slice
JOIN thread_track ON slice.track_id = thread_track.id
JOIN thread ON thread_track.utid = thread.utid
GROUP BY thread.name
ORDER BY events_handled DESC;
```
