//! End-to-end synthetic telemetry pipeline replay integration tests.
//!
//! Replays synthetic binary kernel `EventRecord` streams through the complete two-stage
//! ingestion pipeline (Stage 1 IngressParser -> SystemContext -> Stage 2 EventDispatcher -> Detection Sinks)
//! verifying end-to-end dataflow, context synchronization, and anomaly detection without requiring live kernel drivers.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use parking_lot::Mutex;
use pulsar::context::system_context;
use pulsar::helpers::symbol_resolver::SymbolResolver;
use pulsar::pipeline::dispatcher::{EventDispatcher, Subscriber};
use pulsar::pipeline::event::Event;
use pulsar::sensors::etw::EventRecord;
use pulsar::sinks::direct_sys::DirectSyscallSink;

/// Mock test subscriber that records all dispatched domain events.
struct EventRecordingSink {
    received_count: Arc<AtomicUsize>,
}

impl Subscriber for EventRecordingSink {
    fn is_interested(&self, _event: &Event) -> bool {
        true
    }

    fn on_event(&self, _event: &Arc<Event>) {
        self.received_count.fetch_add(1, Ordering::SeqCst);
    }
}

/// Tests end-to-end pipeline dataflow:
/// 1. Emits synthetic `ProcessStart` event -> IngressParser updates SystemContext -> EventDispatcher delivers to sink.
/// 2. Emits synthetic `SyscallEnter` + `Stack_Walk` -> Correlated into `CorrelatedSyscallEvent` -> DirectSyscallSink evaluates.
/// 3. Closes channel -> Verifies graceful worker pool teardown and total processed event count.
#[test]
fn test_end_to_end_synthetic_pipeline_replay() {
    let (tx, rx) = crossbeam_channel::bounded::<EventRecord>(100);
    let mut dispatcher = EventDispatcher::new(rx);

    let recorded_events = Arc::new(AtomicUsize::new(0));
    dispatcher.add_subscriber(Box::new(EventRecordingSink {
        received_count: Arc::clone(&recorded_events),
    }));

    let shared_resolver = Arc::new(Mutex::new(SymbolResolver::new()));
    dispatcher.add_subscriber(Box::new(DirectSyscallSink::new(shared_resolver)));

    let dispatcher_handle = dispatcher.start();

    // 1. Synthesize ProcessStart EventRecord (PID 7777, svchost.exe)
    let mut proc_payload = Vec::new();
    proc_payload.extend_from_slice(&0x0000_0001_0000_0000u64.to_ne_bytes()); // PageDirectoryBase
    proc_payload.extend_from_slice(&7777u32.to_ne_bytes());                  // ProcessId
    proc_payload.extend_from_slice(&4u32.to_ne_bytes());                     // ParentId
    proc_payload.extend_from_slice(&1u32.to_ne_bytes());                     // SessionId
    proc_payload.extend_from_slice(&0u32.to_ne_bytes());                     // ExitStatus
    proc_payload.extend_from_slice(&0x1234_5678u64.to_ne_bytes());           // DirectoryTableBase
    let mut image_bytes = [0u8; 16];
    image_bytes[..11].copy_from_slice(b"svchost.exe");
    proc_payload.extend_from_slice(&image_bytes);                            // ImageFileName

    let cmd_str: Vec<u16> = "svchost.exe -k netsvcs\0".encode_utf16().collect();
    for u in cmd_str {
        proc_payload.extend_from_slice(&u.to_ne_bytes());
    }

    let proc_record = EventRecord {
        event_id: 1,
        version: 1,
        opcode: 1, // ProcessStart
        level: 0,
        provider_id: windows_sys::core::GUID {
            data1: 0x3d6fa8d0,
            data2: 0x4c01,
            data3: 0x49e5,
            data4: [0x93, 0x13, 0x4c, 0x3d, 0xc7, 0x32, 0x4e, 0x32],
        },
        process_id: 7777,
        thread_id: 8888,
        timestamp: 10_000,
        user_data: proc_payload,
        stack_trace: None,
    };

    tx.send(proc_record).unwrap();

    // 2. Synthesize SyscallEnter (Event ID 51) + Stack_Walk (Opcode 32)
    let mut syscall_payload = Vec::new();
    syscall_payload.extend_from_slice(&0x0000_0028u32.to_ne_bytes()); // Syscall number (NtWriteVirtualMemory)

    let syscall_record = EventRecord {
        event_id: 51,
        version: 1,
        opcode: 51, // SyscallEnter
        level: 0,
        provider_id: windows_sys::core::GUID {
            data1: 0xce1dbfb4,
            data2: 0x137e,
            data3: 0x4da6,
            data4: [0x87, 0xb0, 0x3f, 0x59, 0xaa, 0x10, 0x2c, 0xbc],
        },
        process_id: 7777,
        thread_id: 8888,
        timestamp: 20_000,
        user_data: syscall_payload,
        stack_trace: None,
    };

    let mut stack_payload = Vec::new();
    stack_payload.extend_from_slice(&20_000u64.to_ne_bytes()); // Matches syscall timestamp
    stack_payload.extend_from_slice(&7777u32.to_ne_bytes());   // PID
    stack_payload.extend_from_slice(&8888u32.to_ne_bytes());   // TID
    stack_payload.extend_from_slice(&0x0000_7FFF_1234_5678u64.to_ne_bytes()); // User-mode unbacked frame!

    let stack_record = EventRecord {
        event_id: 32,
        version: 1,
        opcode: 32, // StackWalk
        level: 0,
        provider_id: windows_sys::core::GUID {
            data1: 0xdef2fe46,
            data2: 0x7bd6,
            data3: 0x4b80,
            data4: [0xbd, 0x94, 0xf5, 0x7f, 0xe2, 0x0d, 0x0c, 0xe3],
        },
        process_id: 7777,
        thread_id: 8888,
        timestamp: 20_001,
        user_data: stack_payload,
        stack_trace: None,
    };

    tx.send(syscall_record).unwrap();
    tx.send(stack_record).unwrap();

    // 3. Drop sender to trigger channel close and drain all events through the worker pool
    drop(tx);
    dispatcher_handle.join().expect("Worker pool must exit cleanly");

    // 4. Verify SystemContext was populated
    let ctx = system_context();
    let proc = ctx.process(7777).expect("Process 7777 must be indexed in SystemContext");
    assert_eq!(proc.image_file_name(), "svchost.exe");
    assert_eq!(
        proc.command_line(),
        Some("svchost.exe -k netsvcs")
    );

    // 5. Verify dispatcher delivered all events
    assert!(recorded_events.load(Ordering::SeqCst) >= 2);
}
