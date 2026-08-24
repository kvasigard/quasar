//! Unit tests for the Quasar EDR System Context Engine.
//!
//! Tests state machine invariants, temporal PID isolation, fine-grained in-place mutability,
//! ancestry graph walking, dual-trigger GC tombstones, and multi-source event deduplication.

use std::sync::Arc;
use std::thread;

use super::{
    ConnectionKey, ContextConfig, ExecutionTrigger, HandleObject, HandleTarget,
    InjectionTechnique, LoadedModule, NetworkConnection, ProcessContext, ProcessKey,
    SocketProtocol, SystemContext,
};
use crate::sensors::etw::EventRecord;

/// Tests that recycled OS Process IDs (PIDs) receive distinct synthetic `ProcessKey`s,
/// ensuring that telemetry from a new process never contaminates the history of an exited process.
#[test]
fn test_pid_recycling_and_isolation() {
    let ctx = SystemContext::new_for_test(ContextConfig::for_test());
    let pid = 4500;

    // 1. Process A spawns with PID 4500
    let key_a = ProcessKey::new();
    let proc_a = ProcessContext::new(key_a, None, pid, 1000, 100);
    proc_a.set_image_name("svchost.exe");
    ctx.insert_process(proc_a);

    // Verify lookup by PID returns Process A
    let query_a = ctx.process(pid).expect("Process A should be active");
    assert_eq!(query_a.key(), key_a);
    assert_eq!(query_a.image_file_name(), "svchost.exe");

    // 2. Process A exits
    ctx.exit_process(pid, 0, 200);

    // PID 4500 is now inactive
    assert!(ctx.process(pid).is_none());

    // 3. Process B spawns with recycled PID 4500
    let key_b = ProcessKey::new();
    assert_ne!(key_a, key_b);

    let proc_b = ProcessContext::new(key_b, None, pid, 2000, 300);
    proc_b.set_image_name("malware.exe");
    ctx.insert_process(proc_b);

    // Lookup by PID 4500 now returns Process B
    let query_b = ctx.process(pid).expect("Process B should be active");
    assert_eq!(query_b.key(), key_b);
    assert_eq!(query_b.image_file_name(), "malware.exe");

    // Lookup by synthetic key still resolves Process A (historical state preserved)
    let hist_a = ctx.process_by_key(key_a).expect("Historical Process A must exist");
    assert_eq!(hist_a.key(), key_a);
    assert_eq!(hist_a.image_file_name(), "svchost.exe");
    assert!(!hist_a.is_alive());
}

/// Tests concurrent, fine-grained in-place mutability across multiple threads
/// updating modules, handles, and threads on the same `ProcessContext` without global locks.
#[test]
fn test_concurrent_in_place_interior_mutability() {
    let ctx = SystemContext::new_for_test(ContextConfig::for_test());
    let key = ProcessKey::new();
    let proc = ProcessContext::new(key, None, 1337, 1000, 100);
    let proc_arc = ctx.insert_process(proc);

    let mut handles = Vec::new();

    // Thread 1: Records 100 DLL module loads in-place
    let p1 = Arc::clone(&proc_arc);
    handles.push(thread::spawn(move || {
        for i in 0..100 {
            p1.record_module_load(LoadedModule::new(
                0x7FFF_0000_0000 + (i * 0x10000),
                0x10000,
                format!("module_{}.dll", i),
                None,
                100 + i as i64,
                0,
                0x7FFF_0000_0000,
                false,
            ));
        }
    }));

    // Thread 2: Records 100 open handles in-place
    let p2 = Arc::clone(&proc_arc);
    handles.push(thread::spawn(move || {
        for i in 0..100 {
            p2.record_handle_open(HandleObject {
                handle_value: (i + 1) * 4,
                target: HandleTarget::Process(ProcessKey::from_raw(999)),
                granted_access: 0x1F0FFF,
                open_time: 200 + i as i64,
            });
        }
    }));

    // Thread 3: Records 50 worker thread IDs in-place
    let p3 = Arc::clone(&proc_arc);
    handles.push(thread::spawn(move || {
        for i in 0..50 {
            p3.record_thread_create(10000 + i);
        }
    }));

    for h in handles {
        h.join().unwrap();
    }

    assert_eq!(proc_arc.loaded_modules.read().len(), 100);
    assert_eq!(proc_arc.handles.read().len(), 100);
    assert_eq!(proc_arc.threads.read().len(), 50);
}

/// Tests process lineage tracking and ancestry graph walking backward in time.
#[test]
fn test_process_ancestry_graph_walking() {
    let ctx = SystemContext::new_for_test(ContextConfig::for_test());

    // Build ancestry chain: services.exe (100) -> svchost.exe (200) -> cmd.exe (300) -> powershell.exe (400)
    let k1 = ProcessKey::new();
    let p1 = ProcessContext::new(k1, None, 100, 4, 10);
    p1.set_image_name("services.exe");
    ctx.insert_process(p1);

    let k2 = ProcessKey::new();
    let p2 = ProcessContext::new(k2, Some(k1), 200, 100, 20);
    p2.set_image_name("svchost.exe");
    ctx.insert_process(p2);

    let k3 = ProcessKey::new();
    let p3 = ProcessContext::new(k3, Some(k2), 300, 200, 30);
    p3.set_image_name("cmd.exe");
    ctx.insert_process(p3);

    let k4 = ProcessKey::new();
    let p4 = ProcessContext::new(k4, Some(k3), 400, 300, 40);
    p4.set_image_name("powershell.exe");
    ctx.insert_process(p4);

    let target = ctx.process(400).expect("powershell.exe must exist");
    let ancestors: Vec<_> = target.ancestors().collect();

    assert_eq!(ancestors.len(), 3);
    assert_eq!(ancestors[0].image_file_name(), "cmd.exe");
    assert_eq!(ancestors[1].image_file_name(), "svchost.exe");
    assert_eq!(ancestors[2].image_file_name(), "services.exe");
}

/// Tests dual-trigger garbage collection:
/// - Pinned processes are never evicted.
/// - Expired processes with active children become Tombstones (preserving lineage).
/// - Unpinned expired processes with no children are permanently purged.
#[test]
fn test_retention_tombstones_and_suspicion_pinning() {
    let mut cfg = ContextConfig::for_test();
    cfg.retention_ttl_ms = 10_000;
    let ctx = SystemContext::new_for_test(cfg);

    // Parent spawns at t=0
    let k_parent = ProcessKey::new();
    let parent = ProcessContext::new(k_parent, None, 1000, 4, 0);
    parent.set_image_name("parent.exe");
    ctx.insert_process(parent);

    // Child spawns at t=5
    let k_child = ProcessKey::new();
    let child = ProcessContext::new(k_child, Some(k_parent), 2000, 1000, 5);
    child.set_image_name("child.exe");
    ctx.insert_process(child);

    // Pinned attacker spawns at t=0
    let k_pinned = ProcessKey::new();
    let attacker = ProcessContext::new(k_pinned, None, 3000, 4, 0);
    attacker.set_image_name("attacker.exe");
    let attacker_arc = ctx.insert_process(attacker);
    attacker_arc.pin();

    // Isolated worker spawns at t=0
    let k_worker = ProcessKey::new();
    let worker = ProcessContext::new(k_worker, None, 4000, 4, 0);
    worker.set_image_name("worker.exe");
    ctx.insert_process(worker);

    use crate::context::retention::gc::FILETIME_TICKS_PER_MS;
    const MS: i64 = FILETIME_TICKS_PER_MS;

    // All processes exit at t=10ms
    ctx.exit_process(1000, 0, 10 * MS);
    ctx.exit_process(3000, 0, 10 * MS);
    ctx.exit_process(4000, 0, 10 * MS);

    // Run GC pass at t=30,000ms (elapsed = 29,990ms > TTL 10,000ms)
    let (evicted, tombstones) = ctx.run_gc_pass(30_000 * MS);

    // 1 worker evicted, 1 parent converted to tombstone (since child is alive), 0 pinned evicted
    assert_eq!(evicted, 1);
    assert_eq!(tombstones, 1);

    // Worker is purged
    assert!(ctx.process_by_key(k_worker).is_none());

    // Pinned attacker is retained
    assert!(ctx.process_by_key(k_pinned).is_some());

    // Parent is retained as Tombstone
    let parent_tomb = ctx.process_by_key(k_parent).expect("Parent tombstone must exist");
    assert!(parent_tomb.is_tombstone());

    // Child can still resolve parent through the tombstone
    let child_ref = ctx.process(2000).expect("Child is active");
    let resolved_parent = child_ref.parent().expect("Tombstone parent must be accessible");
    assert_eq!(resolved_parent.image_file_name(), "parent.exe");
}

/// Tests the 4-stage Code Injection state machine and confidence escalation.
#[test]
fn test_stateful_injection_correlation() {
    let ctx = SystemContext::new_for_test(ContextConfig::for_test());

    let k_actor = ProcessKey::new();
    let actor = ProcessContext::new(k_actor, None, 111, 4, 0);
    actor.set_image_name("injector.exe");
    ctx.insert_process(actor);

    let k_target = ProcessKey::new();
    let target = ProcessContext::new(k_target, None, 222, 4, 0);
    target.set_image_name("explorer.exe");
    ctx.insert_process(target);

    let injection = &ctx.injection_correlator;

    // Step 1: OpenProcess with Write/Op access
    injection.on_target_handle_opened(k_actor, k_target, 10);

    // Step 2: VirtualAllocEx allocation
    injection.on_remote_memory_alloc(
        k_actor,
        k_target,
        0x0000_0200_0000,
        0x1000,
        20,
    );

    // Step 3: WriteProcessMemory
    injection.on_remote_memory_write(k_actor, k_target, 0x0000_0200_0000, 30);

    // Step 4: Remote Thread Trigger -> Confirmed
    let confirmed = injection.on_remote_execution(
        k_actor,
        k_target,
        ExecutionTrigger::NtCreateThreadEx,
        InjectionTechnique::ClassicRemoteThread,
        40,
        &ctx.interactions,
        &ctx.processes,
    );

    assert!(confirmed.is_some());
    let alert = confirmed.unwrap();
    if let super::InteractionKind::ProcessInjection(inj) = &alert.kind {
        assert_eq!(inj.technique, InjectionTechnique::ClassicRemoteThread);
    } else {
        panic!("Expected ProcessInjection interaction details");
    }
    assert_eq!(alert.confidence, super::ConfidenceLevel::Confirmed);

    // Verify both processes are automatically pinned for forensic preservation
    let actor_proc = ctx.process_by_key(k_actor).unwrap();
    let target_proc = ctx.process_by_key(k_target).unwrap();
    assert!(actor_proc.is_pinned());
    assert!(target_proc.is_pinned());
}

/// Tests path normalization and deduplication across file and network registries.
#[test]
fn test_file_and_network_registries() {
    let ctx = SystemContext::new_for_test(ContextConfig::for_test());

    // Normalized paths map to identical FileKey
    let (f1, created1) = ctx.files.get_or_create(r"\??\C:\Windows\System32\cmd.exe", 100);
    let (f2, created2) = ctx.files.get_or_create(r"c:/windows/system32/cmd.exe", 100);
    assert!(created1);
    assert!(!created2);
    assert_eq!(f1.key, f2.key);

    f1.set_sha256([0xAA; 32]);
    assert_eq!(f2.sha256(), Some([0xAA; 32]));

    // Record network connection
    let k_proc = ProcessKey::new();
    let conn = NetworkConnection {
        key: ConnectionKey::new(),
        owner_process: k_proc,
        protocol: SocketProtocol::Tcp,
        local_addr: "192.168.1.50:49152".parse().unwrap(),
        remote_addr: "93.184.216.34:443".parse().unwrap(),
        start_time: 100,
        end_time: None,
    };
    let recorded = ctx.network.register_connection(conn);

    assert_eq!(recorded.remote_addr.port(), 443);
    assert_eq!(ctx.network.len(), 1);
}

/// Tests multi-source event deduplication and in-place metadata enrichment.
#[test]
fn test_multi_source_deduplication_and_merging() {
    let _ctx = SystemContext::new_for_test(ContextConfig::for_test());

    // Synthesize process start raw record (48 bytes header + UTF-16 strings)
    let mut payload = Vec::new();
    payload.extend_from_slice(&0x0000_0001_0000_0000u64.to_ne_bytes()); // PageDirectoryBase
    payload.extend_from_slice(&5000u32.to_ne_bytes());                  // ProcessId
    payload.extend_from_slice(&1000u32.to_ne_bytes());                  // ParentId
    payload.extend_from_slice(&1u32.to_ne_bytes());                     // SessionId
    payload.extend_from_slice(&0u32.to_ne_bytes());                     // ExitStatus
    payload.extend_from_slice(&0x1234_5678u64.to_ne_bytes());           // DirectoryTableBase
    let mut image_bytes = [0u8; 16];
    image_bytes[..7].copy_from_slice(b"cmd.exe");
    payload.extend_from_slice(&image_bytes);                            // ImageFileName (16B)

    // Append Command Line "cmd.exe /c whoami\0"
    let cmd_str: Vec<u16> = "cmd.exe /c whoami\0".encode_utf16().collect();
    for u in cmd_str {
        payload.extend_from_slice(&u.to_ne_bytes());
    }

    let record1 = EventRecord {
        event_id: 1,
        version: 1,
        opcode: 1,
        level: 0,
        provider_id: windows_sys::core::GUID {
            data1: 0x3d6fa8d0,
            data2: 0x4c01,
            data3: 0x49e5,
            data4: [0x93, 0x13, 0x4c, 0x3d, 0xc7, 0x32, 0x4e, 0x32],
        },
        process_id: 5000,
        thread_id: 6000,
        timestamp: 1000,
        user_data: payload.clone(),
        stack_trace: None,
    };

    // First arrival: Driver creation callback
    let event1 = crate::context::handlers::handle_process_start(&record1)
        .expect("Must parse process start");
    assert_eq!(event1.pid, 5000);
    assert_eq!(event1.image_file_name, "cmd.exe");

    // Second arrival: ETW process rundown (same PID 5000)
    let event2 = crate::context::handlers::handle_process_start(&record1)
        .expect("Must deduplicate and merge");
    assert_eq!(event2.key, event1.key); // Merged into existing context entity!
}

/// Tests per-process memory address search across interior intervals, boundary conditions,
/// unmapped gaps, system module identification, and centralized FileRegistry linkage.
#[test]
fn test_module_address_resolution_and_boundaries() {
    let ctx = SystemContext::new_for_test(ContextConfig::for_test());
    let pid = 7777;
    let proc_key = ProcessKey::new();

    let proc = ProcessContext::new(proc_key, None, pid, 1000, 100);
    let proc_arc = ctx.insert_process(proc);

    // Register backing files in FileRegistry
    let file_ntdll = ctx.get_or_create_file(r"C:\Windows\System32\ntdll.dll", 100);
    let file_app = ctx.get_or_create_file(r"C:\Program Files\App\app.dll", 100);

    // Module 1: ntdll.dll at [0x7FFE_0000_0000 .. 0x7FFE_0010_0000) (size 0x100000, 1MB)
    let mod1 = LoadedModule::new(
        0x7FFE_0000_0000,
        0x10_0000,
        r"C:\Windows\System32\ntdll.dll",
        Some(file_ntdll.key),
        100,
        0x1234,
        0x7FFE_0000_0000,
        false,
    );

    // Module 2: app.dll at [0x7FFE_0020_0000 .. 0x7FFE_0025_0000) (size 0x50000)
    let mod2 = LoadedModule::new(
        0x7FFE_0020_0000,
        0x5_0000,
        r"C:\Program Files\App\app.dll",
        Some(file_app.key),
        110,
        0x5678,
        0x7FFE_0020_0000,
        false,
    );

    proc_arc.record_module_load(mod1);
    proc_arc.record_module_load(mod2);

    // 1. Inside Module 1
    let resolved = ctx.resolve_module_by_address(pid, 0x7FFE_0005_1234).expect("Should resolve ntdll");
    assert_eq!(resolved.image_name(), r"C:\Windows\System32\ntdll.dll");
    assert!(resolved.is_system());
    assert_eq!(resolved.file_key(), Some(file_ntdll.key));

    // 2. Exact lower boundary (inclusive)
    let at_start = ctx.resolve_module_by_address(pid, 0x7FFE_0000_0000).expect("Base address must resolve");
    assert_eq!(at_start.base_address, 0x7FFE_0000_0000);

    // 3. Exact upper boundary minus 1 (inclusive)
    let at_last_byte = ctx.resolve_module_by_address(pid, 0x7FFE_000F_FFFF).expect("Last byte must resolve");
    assert_eq!(at_last_byte.base_address, 0x7FFE_0000_0000);

    // 4. Exact upper boundary (exclusive -> out of bounds)
    assert!(ctx.resolve_module_by_address(pid, 0x7FFE_0010_0000).is_none());

    // 5. In unmapped memory gap between Module 1 and Module 2
    assert!(ctx.resolve_module_by_address(pid, 0x7FFE_0015_0000).is_none());

    // 6. Address before lowest module
    assert!(ctx.resolve_module_by_address(pid, 0x1000).is_none());

    // 7. Address after highest module
    assert!(ctx.resolve_module_by_address(pid, 0x7FFF_FFFF_FFFF).is_none());

    // 8. Inside Module 2 (Non-system module)
    let resolved_app = ctx.resolve_module_by_address(pid, 0x7FFE_0021_0000).expect("Should resolve app.dll");
    assert_eq!(resolved_app.image_name(), r"C:\Program Files\App\app.dll");
    assert!(!resolved_app.is_system());
    assert_eq!(resolved_app.file_key(), Some(file_app.key));

    // 9. Query via ProcessRef DSL
    let proc_ref = ctx.process(pid).expect("Process must be active");
    assert!(proc_ref.find_module_by_address(0x7FFE_0000_1000).is_some());

    // 10. Module Unload: unmap app.dll and ensure address no longer resolves
    proc_arc.record_module_unload(0x7FFE_0020_0000);
    assert!(ctx.resolve_module_by_address(pid, 0x7FFE_0021_0000).is_none());
    // ntdll.dll remains mapped and resolvable
    assert!(ctx.resolve_module_by_address(pid, 0x7FFE_0000_1000).is_some());
}

/// Tests that the enrichment queue handles non-blocking capacity saturation and automatic trigger on new file creation.
#[test]
fn test_context_enrichment_queue_and_worker() {
    use crate::context::enrichment::{EnrichmentQueue, EnrichmentTask};
    use crate::context::identity::FileKey;

    // 1. Test queue non-blocking try_send and capacity saturation
    let (queue, rx) = EnrichmentQueue::new(2);
    let k1 = FileKey::new();
    let k2 = FileKey::new();
    let k3 = FileKey::new();

    assert!(queue.queue_task(EnrichmentTask::NewFile(k1)));
    assert!(queue.queue_task(EnrichmentTask::NewFile(k2)));
    // Queue is full at capacity 2 -> drops task gracefully without blocking
    assert!(!queue.queue_task(EnrichmentTask::NewFile(k3)));

    // Drain one item and test that queue accepts new task
    assert_eq!(rx.recv().unwrap(), EnrichmentTask::NewFile(k1));
    assert!(queue.queue_task(EnrichmentTask::NewFile(k3)));

    // 2. Test worker lifecycle and clean shutdown
    let (queue, rx) = EnrichmentQueue::new(16);
    let enrichment = Arc::new(queue);
    let worker_handle = Arc::clone(&enrichment).spawn_worker(rx);

    // Enqueue via facade
    assert!(enrichment.queue_task(EnrichmentTask::ScanMemoryVad(ProcessKey::new())));

    // Drop sender to allow worker thread to terminate cleanly
    drop(enrichment);
    worker_handle.join().expect("Enrichment worker should exit cleanly when queue drops");
}

/// Tests that NT device path prefixes (`\??\`, `\\?\`, `\Device\HarddiskVolumeX\`)
/// are cleaned, forward-slashes converted to backslashes, and paths lowercased.
#[test]
fn test_file_path_normalization_nt_prefixes() {
    use crate::context::registries::file_registry::normalize_file_path;

    assert_eq!(
        normalize_file_path(r"\??\C:\Windows\System32\notepad.exe"),
        r"c:\windows\system32\notepad.exe"
    );
    assert_eq!(
        normalize_file_path(r"\\?\C:\Users\Admin/AppData/Local/Temp/malware.exe"),
        r"c:\users\admin\appdata\local\temp\malware.exe"
    );
    let normalized_dev = normalize_file_path(r"\Device\HarddiskVolume2\Windows\explorer.exe");
    assert!(
        normalized_dev.ends_with(r"\windows\explorer.exe")
            && (normalized_dev.starts_with(r"c:")
                || normalized_dev.starts_with(r"d:")
                || normalized_dev.starts_with(r"\\?\globalroot"))
    );
    assert_eq!(
        normalize_file_path("C:/Program Files/Quasar/agent.exe"),
        r"c:\program files\quasar\agent.exe"
    );
}

/// Tests binary deserialization of `FileIo_Create` (Opcode 64) and `FileIo_Name` (Opcode 0) ETW records.
#[test]
fn test_fileio_create_and_name_parsing() {
    use crate::context::handlers::{handle_file_create, handle_file_name};
    use crate::context::CONTEXT;

    let pid = 8812;
    let proc_key = ProcessKey::new();
    let proc = ProcessContext::new(proc_key, None, pid, 1000, 100);
    proc.set_image_name("powershell.exe");
    CONTEXT.insert_process(proc);

    // 1. Synthesize FileIo_Create record (36 bytes header + UTF-16 path)
    let file_obj_1: u64 = 0xFFFF_E000_1234_5678;
    let mut create_payload = Vec::new();
    create_payload.extend_from_slice(&0x1111_0000u64.to_ne_bytes()); // IrpPtr (8B)
    create_payload.extend_from_slice(&0x2222_0000u64.to_ne_bytes()); // TTID (8B)
    create_payload.extend_from_slice(&file_obj_1.to_ne_bytes());     // FileObject (8B)
    create_payload.extend_from_slice(&0x0000_0020u32.to_ne_bytes()); // CreateOptions (4B)
    create_payload.extend_from_slice(&0x0000_0080u32.to_ne_bytes()); // FileAttributes (4B)
    create_payload.extend_from_slice(&0x0000_0001u32.to_ne_bytes()); // ShareAccess (4B)

    let path_str1: Vec<u16> = "\\??\\C:\\Users\\Target\\secret.docx\0".encode_utf16().collect();
    for u in path_str1 {
        create_payload.extend_from_slice(&u.to_ne_bytes());
    }

    let create_record = EventRecord {
        event_id: 64,
        version: 2,
        opcode: 64,
        level: 0,
        provider_id: windows_sys::core::GUID {
            data1: 0x90cbdc39,
            data2: 0x4a3e,
            data3: 0x11d1,
            data4: [0x84, 0xf4, 0x00, 0x00, 0xf8, 0x04, 0x64, 0xe3],
        },
        process_id: pid,
        thread_id: 1234,
        timestamp: 1000,
        user_data: create_payload,
        stack_trace: None,
    };

    let create_event = handle_file_create(&create_record).expect("Must parse FileIo_Create");
    assert_eq!(create_event.pid, pid);
    assert_eq!(create_event.file_object, file_obj_1);
    assert_eq!(create_event.file_path, r"c:\users\target\secret.docx");

    // Verify FileObject mapping in FileRegistry
    let resolved_key = CONTEXT.files.get_key_by_file_object(file_obj_1);
    assert_eq!(resolved_key, Some(create_event.file_key));

    // Verify process touched_files
    let proc_ref = CONTEXT.get_process(pid).unwrap();
    assert!(proc_ref.touched_files.read().contains(&create_event.file_key));

    // 2. Synthesize FileIo_Name record (8 bytes FileObject + UTF-16 path)
    let file_obj_2: u64 = 0xFFFF_E000_9876_5432;
    let mut name_payload = Vec::new();
    name_payload.extend_from_slice(&file_obj_2.to_ne_bytes()); // FileObject (8B)

    let path_str2: Vec<u16> = "C:\\Windows\\System32\\drivers\\etc\\hosts\0".encode_utf16().collect();
    for u in path_str2 {
        name_payload.extend_from_slice(&u.to_ne_bytes());
    }

    let name_record = EventRecord {
        event_id: 0,
        version: 2,
        opcode: 0,
        level: 0,
        provider_id: windows_sys::core::GUID {
            data1: 0x90cbdc39,
            data2: 0x4a3e,
            data3: 0x11d1,
            data4: [0x84, 0xf4, 0x00, 0x00, 0xf8, 0x04, 0x64, 0xe3],
        },
        process_id: pid,
        thread_id: 1234,
        timestamp: 1100,
        user_data: name_payload,
        stack_trace: None,
    };

    let name_event = handle_file_name(&name_record)
        .expect("Must parse FileIo_Name")
        .expect("Must produce FileCreateEvent");
    assert_eq!(name_event.file_object, file_obj_2);
    assert_eq!(name_event.file_path, r"c:\windows\system32\drivers\etc\hosts");
}

/// Tests the end-to-end lifecycle of `FileObject -> FileKey` correlation and unmapping on Close.
#[test]
fn test_file_object_mapping_and_lifecycle() {
    use crate::context::handlers::{handle_file_create, handle_file_operation, handle_file_write};
    use crate::context::models::file::FileOperationKind;
    use crate::context::CONTEXT;

    let pid = 9999;
    let proc_key = ProcessKey::new();
    let proc = ProcessContext::new(proc_key, None, pid, 1000, 100);
    proc.set_image_name("ransomware.exe");
    CONTEXT.insert_process(proc);

    let file_obj: u64 = 0xFFFF_ABCD_0000_1111;

    // 1. Create file
    let mut create_payload = Vec::new();
    create_payload.extend_from_slice(&0u64.to_ne_bytes());
    create_payload.extend_from_slice(&0u64.to_ne_bytes());
    create_payload.extend_from_slice(&file_obj.to_ne_bytes());
    create_payload.extend_from_slice(&0u32.to_ne_bytes());
    create_payload.extend_from_slice(&0u32.to_ne_bytes());
    create_payload.extend_from_slice(&0u32.to_ne_bytes());
    let path: Vec<u16> = "C:\\Data\\database.kdbx\0".encode_utf16().collect();
    for u in path {
        create_payload.extend_from_slice(&u.to_ne_bytes());
    }

    let create_rec = EventRecord {
        event_id: 64,
        version: 2,
        opcode: 64,
        level: 0,
        provider_id: windows_sys::core::GUID {
            data1: 0x90cbdc39,
            data2: 0x4a3e,
            data3: 0x11d1,
            data4: [0x84, 0xf4, 0x00, 0x00, 0xf8, 0x04, 0x64, 0xe3],
        },
        process_id: pid,
        thread_id: 1,
        timestamp: 1000,
        user_data: create_payload,
        stack_trace: None,
    };

    let create_evt = handle_file_create(&create_rec).expect("Create must succeed");
    assert_eq!(CONTEXT.files.get_key_by_file_object(file_obj), Some(create_evt.file_key));

    // 2. Write 65536 bytes to file
    let mut write_payload = Vec::new();
    write_payload.extend_from_slice(&0u64.to_ne_bytes());         // Offset (8B)
    write_payload.extend_from_slice(&0u64.to_ne_bytes());         // IrpPtr (8B)
    write_payload.extend_from_slice(&0u64.to_ne_bytes());         // TTID (8B)
    write_payload.extend_from_slice(&file_obj.to_ne_bytes());     // FileObject (8B)
    write_payload.extend_from_slice(&0u64.to_ne_bytes());         // FileKey (8B)
    write_payload.extend_from_slice(&65536u32.to_ne_bytes());     // IoSize (4B)
    write_payload.extend_from_slice(&0u32.to_ne_bytes());         // IoFlags (4B)

    let write_rec = EventRecord {
        event_id: 68,
        version: 2,
        opcode: 68,
        level: 0,
        provider_id: windows_sys::core::GUID {
            data1: 0x90cbdc39,
            data2: 0x4a3e,
            data3: 0x11d1,
            data4: [0x84, 0xf4, 0x00, 0x00, 0xf8, 0x04, 0x64, 0xe3],
        },
        process_id: pid,
        thread_id: 1,
        timestamp: 1050,
        user_data: write_payload,
        stack_trace: None,
    };

    let write_evt = handle_file_write(&write_rec).expect("Write must succeed");
    assert_eq!(write_evt.file_key, Some(create_evt.file_key));
    assert_eq!(write_evt.io_size, 65536);
    assert!(write_evt.is_write);

    let file_ctx = CONTEXT.files.get_by_key(create_evt.file_key).unwrap();
    assert!(file_ctx.has_writes());

    // 3. Close file (Opcode 66)
    let mut close_payload = Vec::new();
    close_payload.extend_from_slice(&0u64.to_ne_bytes());     // IrpPtr
    close_payload.extend_from_slice(&0u64.to_ne_bytes());     // TTID
    close_payload.extend_from_slice(&file_obj.to_ne_bytes()); // FileObject
    close_payload.extend_from_slice(&0u64.to_ne_bytes());     // FileKey

    let close_rec = EventRecord {
        event_id: 66,
        version: 2,
        opcode: 66,
        level: 0,
        provider_id: windows_sys::core::GUID {
            data1: 0x90cbdc39,
            data2: 0x4a3e,
            data3: 0x11d1,
            data4: [0x84, 0xf4, 0x00, 0x00, 0xf8, 0x04, 0x64, 0xe3],
        },
        process_id: pid,
        thread_id: 1,
        timestamp: 1100,
        user_data: close_payload,
        stack_trace: None,
    };

    let close_evt = handle_file_operation(&close_rec).expect("Close must succeed");
    assert_eq!(close_evt.operation, FileOperationKind::Close);
    assert_eq!(close_evt.file_key, Some(create_evt.file_key));

    // FileObject must be unmapped upon Close
    assert_eq!(CONTEXT.files.get_key_by_file_object(file_obj), None);
}

/// Tests ProcessRef and SystemContext query APIs for inspecting touched files, writes, and history.
#[test]
fn test_file_query_dsl() {
    let ctx = SystemContext::new_for_test(ContextConfig::for_test());
    let pid = 3333;
    let proc_key = ProcessKey::new();

    let proc = ProcessContext::new(proc_key, None, pid, 1000, 100);
    let proc_arc = ctx.insert_process(proc);

    let f1 = ctx.get_or_create_file(r"C:\Test\doc1.txt", 100);
    let f2 = ctx.get_or_create_file(r"C:\Test\doc2.txt", 110);

    // Record access
    proc_arc.record_file_access(f1.key);
    proc_arc.record_file_access(f2.key);

    // f2 receives write
    f2.record_access(crate::context::models::file::FileAccessRecord {
        operation: crate::context::models::file::FileOperationKind::Write,
        timestamp: 120,
        bytes_transferred: 1024,
        is_write: true,
    });

    // 1. SystemContext touched_files by PID
    let touched_pid = ctx.touched_files(pid);
    assert_eq!(touched_pid.len(), 2);

    // 2. SystemContext touched_files by key
    let touched_key = ctx.touched_files_by_key(proc_key);
    assert_eq!(touched_key.len(), 2);

    // 3. ProcessRef fluent query
    let proc_ref = ctx.process(pid).expect("Process must exist");
    assert_eq!(proc_ref.touched_file_keys().len(), 2);
    assert_eq!(proc_ref.touched_files().len(), 2);

    let modified = proc_ref.modified_files();
    assert_eq!(modified.len(), 1);
    assert_eq!(modified[0].path(), r"c:\test\doc2.txt");

    // 4. File access history
    let history = ctx.file_access_history(f2.key);
    assert_eq!(history.len(), 1);
    assert!(history[0].is_write);
    assert_eq!(history[0].bytes_transferred, 1024);
}

/// Tests defensive handling and error rejection on truncated binary payloads.
#[test]
fn test_truncated_file_payload_rejection() {
    use crate::context::handlers::{handle_file_create, handle_file_operation, handle_file_read_write};
    use crate::error::HandlerError;

    let short_record = EventRecord {
        event_id: 64,
        version: 2,
        opcode: 64,
        level: 0,
        provider_id: windows_sys::core::GUID {
            data1: 0x90cbdc39,
            data2: 0x4a3e,
            data3: 0x11d1,
            data4: [0x84, 0xf4, 0x00, 0x00, 0xf8, 0x04, 0x64, 0xe3],
        },
        process_id: 100,
        thread_id: 200,
        timestamp: 100,
        user_data: vec![0u8; 10], // Too short for all structs
        stack_trace: None,
    };

    assert!(matches!(
        handle_file_create(&short_record),
        Err(HandlerError::PayloadTooShort { expected: 36, actual: 10 })
    ));
    assert!(matches!(
        handle_file_read_write(&short_record, true),
        Err(HandlerError::PayloadTooShort { expected: 48, actual: 10 })
    ));
    assert!(matches!(
        handle_file_operation(&short_record),
        Err(HandlerError::PayloadTooShort { expected: 24, actual: 10 })
    ));
}

/// Tests that attaching PeInfo to a FileContext caches it centrally and shares it across multiple processes.
#[test]
fn test_file_format_info_pe_caching_and_sharing() {
    use std::sync::Arc;
    use crate::context::models::file::FileFormatInfo;
    use crate::context::CONTEXT;
    use crate::helpers::pe::{PeExport, PeExportDirectory, PeInfo, PeSection};

    let path = r"C:\Windows\System32\dummy_syscall.dll";
    let file_ctx = CONTEXT.get_or_create_file(path, 1000);
    let file_key = file_ctx.key;

    // Initially format info is Unknown
    assert!(!file_ctx.is_pe());
    assert!(file_ctx.pe_info().is_none());

    // Create synthetic PeInfo
    let mut by_name = std::collections::HashMap::new();
    by_name.insert("NtTestSyscall".to_string(), 0x1020);

    let export_dir = PeExportDirectory {
        dll_name: Some("dummy_syscall.dll".to_string()),
        export_table_rva: 0x2000,
        export_table_size: 0x1000,
        ordinal_base: 1,
        exports: vec![PeExport {
            name: Some("NtTestSyscall".to_string()),
            ordinal: 1,
            rva: 0x1020,
            forwarder: None,
        }],
        by_name,
        by_ordinal: std::collections::HashMap::new(),
    };

    let pe_info = Arc::new(PeInfo {
        is_64bit: true,
        machine: 0x8664,
        characteristics: 0x2000,
        subsystem: 3,
        image_base: 0x180000000,
        size_of_image: 0x10000,
        entry_point_rva: 0x1000,
        size_of_headers: 0x400,
        sections: vec![PeSection {
            name: ".text".to_string(),
            virtual_address: 0x1000,
            virtual_size: 0x1000,
            raw_data_offset: 0x400,
            raw_data_size: 0x400,
            characteristics: 0x60000020,
        }],
        exports: Some(export_dir),
    });

    // Attach to file context via SystemContext facade
    CONTEXT.set_file_format_info(file_key, FileFormatInfo::Pe(Arc::clone(&pe_info)));

    // Verify file_ctx has PE info
    assert!(file_ctx.is_pe());
    let retrieved_pe = file_ctx.pe_info().expect("Must have PeInfo");
    assert_eq!(retrieved_pe.find_export_by_name("NtTestSyscall"), Some(0x1020));

    // Verify query through SystemContext facade
    let facade_pe = CONTEXT.file_pe_info(file_key).expect("Facade must resolve PeInfo");
    assert_eq!(facade_pe.image_base, 0x180000000);

    // Create two distinct processes loading this module
    let pid1 = 6001;
    let proc_key1 = ProcessKey::new();
    let proc1 = ProcessContext::new(proc_key1, None, pid1, 1000, 100);
    CONTEXT.insert_process(proc1);

    let pid2 = 6002;
    let proc_key2 = ProcessKey::new();
    let proc2 = ProcessContext::new(proc_key2, None, pid2, 1000, 100);
    CONTEXT.insert_process(proc2);

    let proc_ref1 = CONTEXT.get_process(pid1).unwrap();
    let proc_ref2 = CONTEXT.get_process(pid2).unwrap();

    proc_ref1.record_file_access(file_key);
    proc_ref2.record_file_access(file_key);

    // Both processes access the exact same underlying Arc<PeInfo> pointer in memory
    let f1 = CONTEXT.files.get_by_key(file_key).unwrap();
    let f2 = CONTEXT.files.get_by_key(file_key).unwrap();

    let pe1 = f1.pe_info().unwrap();
    let pe2 = f2.pe_info().unwrap();

    assert!(Arc::ptr_eq(&pe1, &pe2));
}

/// Tests that ModuleInfo metadata is shared via Flyweight pattern (Arc pointer equality)
/// across multiple processes, and that ProcessContext::is_alive operates correctly from exit_time.
#[test]
fn test_loaded_module_flyweight_sharing_and_liveness() {
    let ctx = SystemContext::new_for_test(ContextConfig::for_test());

    // 1. Test is_alive lifecycle
    let k1 = ProcessKey::new();
    let proc1 = ProcessContext::new(k1, None, 8001, 1000, 100);
    assert!(proc1.is_alive());
    assert_eq!(proc1.exit_time.load(std::sync::atomic::Ordering::Relaxed), 0);

    proc1.mark_terminated(0, 500);
    assert!(!proc1.is_alive());
    assert_eq!(proc1.exit_time.load(std::sync::atomic::Ordering::Relaxed), 500);

    // 2. Test Flyweight ModuleInfo sharing across processes
    let file = ctx.get_or_create_file(r"C:\Windows\System32\kernel32.dll", 100);
    let info1 = ctx.get_or_create_module_info(
        Some(file.key),
        r"C:\Windows\System32\kernel32.dll",
        0x100000,
        0xABCD,
        0x7FFE_0000_0000,
    );
    let info2 = ctx.get_or_create_module_info(
        Some(file.key),
        r"C:\Windows\System32\kernel32.dll",
        0x100000,
        0xABCD,
        0x7FFE_0000_0000,
    );

    // Identical heap instance shared across processes
    assert!(Arc::ptr_eq(&info1, &info2));

    let mod_p1 = LoadedModule::with_info(0x7FFE_0000_0000, 100, false, info1);
    let mod_p2 = LoadedModule::with_info(0x7FFE_0000_0000, 150, false, info2);

    assert!(Arc::ptr_eq(&mod_p1.info, &mod_p2.info));
    assert_eq!(mod_p1.image_name(), r"C:\Windows\System32\kernel32.dll");
    assert!(mod_p1.is_system());
    assert_eq!(mod_p1.file_key(), Some(file.key));
}

/// Tests that InteractionRegistry prunes secondary indices (source_index & target_index)
/// when old interaction records are evicted from the ring buffer, preventing memory leaks.
#[test]
fn test_interaction_registry_secondary_index_pruning() {
    use crate::context::identity::EntityId;
    use crate::context::models::interaction::{ConfidenceLevel, InteractionKind, InteractionRecord};
    use crate::context::registries::InteractionRegistry;

    // Create registry with capacity of 2 items
    let registry = InteractionRegistry::new(2);

    let p1 = EntityId::Process(ProcessKey::new());
    let p2 = EntityId::Process(ProcessKey::new());

    let r1 = InteractionRecord::new(InteractionKind::ProcessSpawn, p1, p2, 100, ConfidenceLevel::Confirmed, "spawn");
    let r2 = InteractionRecord::new(InteractionKind::ProcessSpawn, p1, p2, 101, ConfidenceLevel::Confirmed, "spawn");
    let r3 = InteractionRecord::new(InteractionKind::ProcessSpawn, p1, p2, 102, ConfidenceLevel::Confirmed, "spawn");

    let id1 = r1.id;
    let id2 = r2.id;
    let id3 = r3.id;

    registry.record(r1);
    registry.record(r2);
    assert_eq!(registry.inbound(p2).len(), 2);

    // Recording r3 evicts r1 from bounded buffer
    registry.record(r3);
    let inbound = registry.inbound(p2);
    assert_eq!(inbound.len(), 2);
    assert!(!inbound.iter().any(|r| r.id == id1));
    assert!(inbound.iter().any(|r| r.id == id2));
    assert!(inbound.iter().any(|r| r.id == id3));
}

/// Tests atomic concurrent deduplication in FileRegistry and ProcessTree across multiple threads.
#[test]
fn test_file_registry_and_process_tree_concurrent_dedup() {
    let ctx = SystemContext::new_for_test(ContextConfig::for_test());
    let mut handles = Vec::new();

    // 10 threads concurrently calling get_or_create for the same file path
    for _ in 0..10 {
        let files = Arc::clone(&ctx.files);
        handles.push(std::thread::spawn(move || {
            let (file, _) = files.get_or_create(r"C:\Windows\System32\drivers\etc\hosts", 100);
            file.key
        }));
    }

    let mut keys = Vec::new();
    for h in handles {
        keys.push(h.join().unwrap());
    }

    // All threads must receive the exact same synthetic FileKey
    let first_key = keys[0];
    assert!(keys.iter().all(|&k| k == first_key));
    assert_eq!(ctx.files.len(), 1);

    // 10 threads concurrently calling get_or_create_by_pid for the same PID
    let mut proc_handles = Vec::new();
    for _ in 0..10 {
        let processes = Arc::clone(&ctx.processes);
        proc_handles.push(std::thread::spawn(move || {
            processes.get_or_create_by_pid(9999, 100).key
        }));
    }

    let mut proc_keys = Vec::new();
    for h in proc_handles {
        proc_keys.push(h.join().unwrap());
    }

    let first_proc_key = proc_keys[0];
    assert!(proc_keys.iter().all(|&k| k == first_proc_key));
    assert_eq!(ctx.processes.active_process_count(), 1);
}

/// Tests in-place enrichment of command line and application metadata on repeat process events.
#[test]
fn test_process_command_line_in_place_enrichment() {
    let ctx = SystemContext::new_for_test(ContextConfig::for_test());
    let key = ProcessKey::new();
    let proc = ProcessContext::new(key, None, 5555, 4, 100);
    proc.set_image_name("powershell.exe");
    ctx.insert_process(proc);

    let proc_ref = ctx.process(5555).expect("Process 5555 must be active");
    assert!(proc_ref.command_line().is_none());

    // In-place enrichment update
    proc_ref.context().set_command_line("powershell.exe -NoProfile -ExecutionPolicy Bypass");
    proc_ref.context().set_package_full_name("Microsoft.WindowsPowerShell");
    proc_ref.context().set_application_id("PowerShellApp");

    assert_eq!(
        proc_ref.command_line().as_deref(),
        Some("powershell.exe -NoProfile -ExecutionPolicy Bypass")
    );
    assert_eq!(
        proc_ref.package_full_name().as_deref(),
        Some("Microsoft.WindowsPowerShell")
    );
    assert_eq!(
        proc_ref.application_id().as_deref(),
        Some("PowerShellApp")
    );
}

/// Tests extended ProcessRef query DSL methods including token privileges and handle target filtering.
#[test]
fn test_process_ref_dsl_extended_queries_and_handles() {
    use crate::context::identity::FileKey;
    use crate::context::models::handle::{HandleObject, HandleTarget};
    use crate::context::models::token::{IntegrityLevel, TokenContext};

    let ctx = SystemContext::new_for_test(ContextConfig::for_test());
    let key_victim = ProcessKey::new();
    let victim = ProcessContext::new(key_victim, None, 7000, 4, 100);
    victim.set_image_name("lsass.exe");
    ctx.insert_process(victim);

    let key_actor = ProcessKey::new();
    let actor = ProcessContext::new(key_actor, None, 8000, 4, 100);
    actor.set_image_name("mimikatz.exe");

    // Configure token
    {
        let mut tok = TokenContext::new();
        tok.is_elevated = true;
        tok.integrity = IntegrityLevel::System;
        tok.enable_privilege("SeDebugPrivilege");
        *actor.token.write() = tok;
    }

    // Record handle to victim process with VM_READ and VM_WRITE
    actor.record_handle_open(HandleObject {
        handle_value: 0x100,
        target: HandleTarget::Process(key_victim),
        granted_access: 0x1FFFFF, // PROCESS_ALL_ACCESS
        open_time: 105,
    });

    let file_key = FileKey::new();
    actor.record_handle_open(HandleObject {
        handle_value: 0x104,
        target: HandleTarget::File(file_key),
        granted_access: 0x80000000,
        open_time: 106,
    });

    ctx.insert_process(actor);

    let actor_ref = ctx.process(8000).expect("Actor process must exist");
    assert!(actor_ref.is_elevated());
    assert_eq!(actor_ref.integrity(), IntegrityLevel::System);
    assert!(actor_ref.has_privilege("SeDebugPrivilege"));
    assert!(!actor_ref.has_privilege("SeTcbPrivilege"));

    let handles_to_victim = actor_ref.handles_to_process(key_victim);
    assert_eq!(handles_to_victim.len(), 1);
    assert!(handles_to_victim[0].has_process_write_access());
    assert!(handles_to_victim[0].has_process_inject_access());
    assert!(handles_to_victim[0].has_process_read_access());

    let handles_to_file = actor_ref.handles_to_file(file_key);
    assert_eq!(handles_to_file.len(), 1);
    assert_eq!(handles_to_file[0].handle_value, 0x104);
}

/// Tests FileRef and ThreadRef query DSL wrappers and process relationship traversals.
#[test]
fn test_file_ref_and_thread_ref_query_dsl() {
    use crate::context::identity::ThreadKey;
    use crate::context::models::file::{FileAccessRecord, FileOperationKind};
    use crate::context::models::thread::ThreadContext;
    use crate::context::query::thread_query::ThreadRef;

    let ctx = SystemContext::new_for_test(ContextConfig::for_test());

    // 1. Create file entity
    let file = ctx.get_or_create_file(r"C:\Windows\System32\drivers\etc\hosts", 100);
    file.record_access(FileAccessRecord {
        operation: FileOperationKind::Write,
        timestamp: 105,
        bytes_transferred: 512,
        is_write: true,
    });

    // 2. Create processes accessing this file
    let k_proc1 = ProcessKey::new();
    let proc1 = ProcessContext::new(k_proc1, None, 4401, 4, 100);
    proc1.set_image_name("editor.exe");
    proc1.record_file_access(file.key);
    ctx.insert_process(proc1);

    let k_proc2 = ProcessKey::new();
    let proc2 = ProcessContext::new(k_proc2, None, 4402, 4, 100);
    proc2.set_image_name("reader.exe");
    proc2.record_file_access(file.key);
    ctx.insert_process(proc2);

    // Query file via DSL
    let file_ref = ctx.file(r"C:\Windows\System32\drivers\etc\hosts").expect("File must be queried");
    assert_eq!(file_ref.file_name(), "hosts");
    assert!(file_ref.has_writes());
    assert!(file_ref.is_modified());

    let accessing = file_ref.accessing_processes();
    assert_eq!(accessing.len(), 2);
    assert!(accessing.iter().any(|p| p.pid() == 4401));
    assert!(accessing.iter().any(|p| p.pid() == 4402));

    let modifying = file_ref.modifying_processes();
    assert_eq!(modifying.len(), 2);

    // Query thread via DSL
    let t_key = ThreadKey::new();
    let thread = Arc::new(ThreadContext::new(t_key, k_proc1, 9901, 0x7FFE_1000, 100));
    let thread_ref = ThreadRef::new(&ctx, thread);

    assert_eq!(thread_ref.tid(), 9901);
    assert!(thread_ref.is_alive());
    assert_eq!(thread_ref.start_address(), 0x7FFE_1000);
    assert_eq!(thread_ref.owner_process().unwrap().pid(), 4401);
}

/// Tests NetworkQuery DSL filtering by process, port, protocol, and external IP.
#[test]
fn test_network_query_dsl() {
    use std::net::SocketAddr;
    use crate::context::models::network::{NetworkConnection, SocketProtocol};

    let ctx = SystemContext::new_for_test(ContextConfig::for_test());
    let k_proc = ProcessKey::new();
    let proc = ProcessContext::new(k_proc, None, 6001, 4, 100);
    proc.set_image_name("curl.exe");
    ctx.insert_process(proc);

    let conn1 = NetworkConnection {
        key: ConnectionKey::new(),
        owner_process: k_proc,
        protocol: SocketProtocol::Tcp,
        local_addr: "192.168.1.50:52100".parse::<SocketAddr>().unwrap(),
        remote_addr: "93.184.216.34:443".parse::<SocketAddr>().unwrap(), // example.com
        start_time: 100,
        end_time: None,
    };

    let conn2 = NetworkConnection {
        key: ConnectionKey::new(),
        owner_process: k_proc,
        protocol: SocketProtocol::Udp,
        local_addr: "127.0.0.1:53000".parse::<SocketAddr>().unwrap(),
        remote_addr: "127.0.0.1:53".parse::<SocketAddr>().unwrap(), // localhost DNS
        start_time: 101,
        end_time: None,
    };

    ctx.network.register_connection(conn1);
    ctx.network.register_connection(conn2);

    let net_query = ctx.network_query();
    assert_eq!(net_query.by_process(k_proc).len(), 2);
    assert_eq!(net_query.by_remote_port(443).len(), 1);
    assert_eq!(net_query.by_protocol(SocketProtocol::Tcp).len(), 1);
    assert_eq!(net_query.by_protocol(SocketProtocol::Udp).len(), 1);

    let external = net_query.outbound_external();
    assert_eq!(external.len(), 1);
    assert_eq!(external[0].remote_addr.port(), 443);
}

/// Tests that digital signature verification verdicts stored on FileContext are shared across
/// all processes accessing or executing the binary with zero CPU overhead.
#[test]
fn test_file_digital_signature_caching_and_process_sharing() {
    use crate::context::models::file::{DigitalSignature, SignatureStatus, SignatureType};

    let ctx = SystemContext::new_for_test(ContextConfig::for_test());

    // 1. Register shared binary in FileRegistry
    let file = ctx.get_or_create_file(r"C:\Windows\System32\svchost.exe", 100);
    assert_eq!(file.signature_status(), SignatureStatus::Unchecked);

    // 2. Simulate background verification by setting the verified DigitalSignature
    let sig = DigitalSignature {
        status: SignatureStatus::SignedVerified,
        signature_type: Some(SignatureType::Catalog),
        signer_name: Some("Microsoft Windows".to_string()),
        issuer_name: Some("Microsoft Root Certificate Authority 2010".to_string()),
        is_microsoft: true,
        win32_error: 0,
        verification_timestamp: 150,
    };
    file.set_signature(sig);

    // 3. Create two independent processes executing svchost.exe
    let k_proc1 = ProcessKey::new();
    let proc1 = ProcessContext::new(k_proc1, None, 1001, 4, 200);
    proc1.set_image_name(r"C:\Windows\System32\svchost.exe");
    proc1.record_file_access(file.key);
    ctx.insert_process(proc1);

    let k_proc2 = ProcessKey::new();
    let proc2 = ProcessContext::new(k_proc2, None, 1002, 4, 205);
    proc2.set_image_name(r"C:\Windows\System32\svchost.exe");
    proc2.record_file_access(file.key);
    ctx.insert_process(proc2);

    // 4. Query both processes via ProcessRef DSL
    let p1_ref = ctx.process(1001).expect("Process 1 must exist");
    let p2_ref = ctx.process(1002).expect("Process 2 must exist");

    assert!(p1_ref.is_image_signed());
    assert!(p1_ref.is_image_microsoft());
    assert!(p2_ref.is_image_signed());
    assert!(p2_ref.is_image_microsoft());

    // Query file via FileRef DSL
    let file_ref = ctx.file(r"C:\Windows\System32\svchost.exe").expect("FileRef must resolve");
    assert_eq!(file_ref.signature_status(), SignatureStatus::SignedVerified);
    assert!(file_ref.is_trusted());
    assert!(file_ref.is_microsoft());
    assert_eq!(file_ref.signer_name().as_deref(), Some("Microsoft Windows"));
    assert_eq!(
        file_ref.issuer_name().as_deref(),
        Some("Microsoft Root Certificate Authority 2010")
    );
}




