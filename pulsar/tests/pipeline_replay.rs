//! End-to-end synthetic telemetry pipeline replay integration tests.
//!
//! Replays synthetic binary kernel `EventRecord` streams through the complete two-stage
//! ingestion pipeline (Stage 1 IngressParser -> SystemContext -> Stage 2 EventDispatcher -> Detection Sinks)
//! verifying end-to-end dataflow, context synchronization, and anomaly detection without requiring live kernel drivers.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use pulsar::context::system_context;
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

    dispatcher.add_subscriber(Box::new(DirectSyscallSink::new()));

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

    // 3. Synthesize FileIo_Create (Opcode 64) + FileIo_Write (Opcode 68) + FileIo_Close (Opcode 66)
    let file_obj: u64 = 0xFFFF_E000_5555_4444;
    let mut file_create_payload = Vec::new();
    file_create_payload.extend_from_slice(&0u64.to_ne_bytes());
    file_create_payload.extend_from_slice(&0u64.to_ne_bytes());
    file_create_payload.extend_from_slice(&file_obj.to_ne_bytes());
    file_create_payload.extend_from_slice(&0u32.to_ne_bytes());
    file_create_payload.extend_from_slice(&0u32.to_ne_bytes());
    file_create_payload.extend_from_slice(&0u32.to_ne_bytes());
    let path: Vec<u16> = "C:\\Windows\\System32\\drivers\\etc\\hosts\0".encode_utf16().collect();
    for u in path {
        file_create_payload.extend_from_slice(&u.to_ne_bytes());
    }

    let file_create_record = EventRecord {
        event_id: 64,
        version: 2,
        opcode: 64, // FileIo_Create
        level: 0,
        provider_id: windows_sys::core::GUID {
            data1: 0x90cbdc39,
            data2: 0x4a3e,
            data3: 0x11d1,
            data4: [0x84, 0xf4, 0x00, 0x00, 0xf8, 0x04, 0x64, 0xe3],
        },
        process_id: 7777,
        thread_id: 8888,
        timestamp: 30_000,
        user_data: file_create_payload,
        stack_trace: None,
    };

    let mut file_write_payload = Vec::new();
    file_write_payload.extend_from_slice(&0u64.to_ne_bytes());         // Offset
    file_write_payload.extend_from_slice(&0u64.to_ne_bytes());         // IrpPtr
    file_write_payload.extend_from_slice(&0u64.to_ne_bytes());         // TTID
    file_write_payload.extend_from_slice(&file_obj.to_ne_bytes());     // FileObject
    file_write_payload.extend_from_slice(&0u64.to_ne_bytes());         // FileKey
    file_write_payload.extend_from_slice(&2048u32.to_ne_bytes());      // IoSize
    file_write_payload.extend_from_slice(&0u32.to_ne_bytes());         // IoFlags

    let file_write_record = EventRecord {
        event_id: 68,
        version: 2,
        opcode: 68, // FileIo_Write
        level: 0,
        provider_id: windows_sys::core::GUID {
            data1: 0x90cbdc39,
            data2: 0x4a3e,
            data3: 0x11d1,
            data4: [0x84, 0xf4, 0x00, 0x00, 0xf8, 0x04, 0x64, 0xe3],
        },
        process_id: 7777,
        thread_id: 8888,
        timestamp: 30_500,
        user_data: file_write_payload,
        stack_trace: None,
    };

    let mut file_close_payload = Vec::new();
    file_close_payload.extend_from_slice(&0u64.to_ne_bytes());
    file_close_payload.extend_from_slice(&0u64.to_ne_bytes());
    file_close_payload.extend_from_slice(&file_obj.to_ne_bytes());
    file_close_payload.extend_from_slice(&0u64.to_ne_bytes());

    let file_close_record = EventRecord {
        event_id: 66,
        version: 2,
        opcode: 66, // FileIo_Close
        level: 0,
        provider_id: windows_sys::core::GUID {
            data1: 0x90cbdc39,
            data2: 0x4a3e,
            data3: 0x11d1,
            data4: [0x84, 0xf4, 0x00, 0x00, 0xf8, 0x04, 0x64, 0xe3],
        },
        process_id: 7777,
        thread_id: 8888,
        timestamp: 31_000,
        user_data: file_close_payload,
        stack_trace: None,
    };

    tx.send(file_create_record).unwrap();
    tx.send(file_write_record).unwrap();
    tx.send(file_close_record).unwrap();

    // 4. Drop sender to trigger channel close and drain all events through the worker pool
    drop(tx);
    dispatcher_handle.join().expect("Worker pool must exit cleanly");

    // 5. Verify SystemContext was populated
    let ctx = system_context();
    let proc = ctx.process(7777).expect("Process 7777 must be indexed in SystemContext");
    assert_eq!(proc.image_file_name(), "svchost.exe");
    assert_eq!(
        proc.command_line().as_deref(),
        Some("svchost.exe -k netsvcs")
    );

    // Verify FileRegistry and ProcessContext touched files
    let touched = proc.touched_files();
    assert_eq!(touched.len(), 1);
    assert_eq!(touched[0].path(), r"c:\windows\system32\drivers\etc\hosts");
    assert!(touched[0].has_writes());

    let modified = proc.modified_files();
    assert_eq!(modified.len(), 1);
    assert_eq!(modified[0].path(), r"c:\windows\system32\drivers\etc\hosts");

    let file_in_registry = ctx.file(r"c:\windows\system32\drivers\etc\hosts");
    assert!(file_in_registry.is_some());

    // 6. Verify dispatcher delivered all events
    assert!(recorded_events.load(Ordering::SeqCst) >= 5);
}
