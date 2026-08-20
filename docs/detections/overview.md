# Detection Sinks Overview

Detection sinks are the analytical brains of Quasar. While the earlier stages of the pipeline focus on collecting, cleaning, and indexing telemetry, sinks focus entirely on security logic: inspecting system events and querying the knowledge graph to detect evasive attack techniques, privilege escalation, and suspicious anomalies.

```
 [Stage 2 Event Dispatcher]
         │
         ├──► Direct Syscalls Sink (Call Stack Analysis & Unbacked Memory)
         │
         ├──► Stateful Injection Correlator (Multi-Step Remote Injections)
         │
         └──► Future Behavioral Sinks (PPID Spoofing, Token Abuse, Ransomware)
```

## Active Detections

* [Direct System Calls](direct-syscalls.md): Detection of user-mode hook bypass techniques (SysWhispers, Hell's Gate, Halo's Gate, Tartarus' Gate) through return address boundary filtering and PE export symbol resolution.
* [Stateful Code Injection Correlator](injection-correlator.md): Multi-step behavioral correlation tracking memory allocation, cross-process writes, and remote thread creation across time.

## Writing a New Detection Sink

Every detection sink implements the `Subscriber` trait:

```rust
pub trait Subscriber {
    fn is_interested(&self, event: &Event) -> bool;
    fn on_event(&self, event: &Arc<Event>);
}
```

The `is_interested` method acts as a fast filter, allowing the dispatcher to skip sinks that do not care about a specific event type. When an event matches, `on_event` is called with a shared pointer to the domain event.

To register your sink, add it to the event dispatcher during startup in `main.rs`:

```rust
dispatcher.add_subscriber(Box::new(YourNewDetectionSink));
```
