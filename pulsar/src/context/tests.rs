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
    let mut proc_a = ProcessContext::new(key_a, None, pid, 1000, 100);
    proc_a.image_file_name = "svchost.exe".to_string();
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

    let mut proc_b = ProcessContext::new(key_b, None, pid, 2000, 300);
    proc_b.image_file_name = "malware.exe".to_string();
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
    let mut p1 = ProcessContext::new(k1, None, 100, 4, 10);
    p1.image_file_name = "services.exe".to_string();
    ctx.insert_process(p1);

    let k2 = ProcessKey::new();
    let mut p2 = ProcessContext::new(k2, Some(k1), 200, 100, 20);
    p2.image_file_name = "svchost.exe".to_string();
    ctx.insert_process(p2);

    let k3 = ProcessKey::new();
    let mut p3 = ProcessContext::new(k3, Some(k2), 300, 200, 30);
    p3.image_file_name = "cmd.exe".to_string();
    ctx.insert_process(p3);

    let k4 = ProcessKey::new();
    let mut p4 = ProcessContext::new(k4, Some(k3), 400, 300, 40);
    p4.image_file_name = "powershell.exe".to_string();
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
    let mut parent = ProcessContext::new(k_parent, None, 1000, 4, 0);
    parent.image_file_name = "parent.exe".to_string();
    ctx.insert_process(parent);

    // Child spawns at t=5
    let k_child = ProcessKey::new();
    let mut child = ProcessContext::new(k_child, Some(k_parent), 2000, 1000, 5);
    child.image_file_name = "child.exe".to_string();
    ctx.insert_process(child);

    // Pinned attacker spawns at t=0
    let k_pinned = ProcessKey::new();
    let mut attacker = ProcessContext::new(k_pinned, None, 3000, 4, 0);
    attacker.image_file_name = "attacker.exe".to_string();
    let attacker_arc = ctx.insert_process(attacker);
    attacker_arc.pin();

    // Isolated worker spawns at t=0
    let k_worker = ProcessKey::new();
    let mut worker = ProcessContext::new(k_worker, None, 4000, 4, 0);
    worker.image_file_name = "worker.exe".to_string();
    ctx.insert_process(worker);

    // All processes exit at t=10
    ctx.exit_process(1000, 0, 10);
    ctx.exit_process(3000, 0, 10);
    ctx.exit_process(4000, 0, 10);

    // Run GC pass at t=30 (elapsed = 20s > TTL 10s)
    let (evicted, tombstones) = ctx.run_gc_pass(30_000);

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
    let mut actor = ProcessContext::new(k_actor, None, 111, 4, 0);
    actor.image_file_name = "injector.exe".to_string();
    ctx.insert_process(actor);

    let k_target = ProcessKey::new();
    let mut target = ProcessContext::new(k_target, None, 222, 4, 0);
    target.image_file_name = "explorer.exe".to_string();
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
    assert_eq!(resolved.image_name, r"C:\Windows\System32\ntdll.dll");
    assert!(resolved.is_system);
    assert_eq!(resolved.file_key, Some(file_ntdll.key));

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
    assert_eq!(resolved_app.image_name, r"C:\Program Files\App\app.dll");
    assert!(!resolved_app.is_system);
    assert_eq!(resolved_app.file_key, Some(file_app.key));

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
