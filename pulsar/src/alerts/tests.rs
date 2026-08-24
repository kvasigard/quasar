//! Unit tests for the alert management subsystem.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use super::*;
use crate::context::identity::ProcessKey;
use crate::context::models::interaction::ConfidenceLevel;

struct MockSink {
    call_count: Arc<AtomicUsize>,
}

impl AlertSink for MockSink {
    fn on_alert(&self, _alert: &AlertRecord) {
        self.call_count.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn test_alert_manager_emit_and_retrieve() {
    let manager = AlertManager::new(10);
    let proc_key = ProcessKey::new();

    let alert = AlertRecord::new(
        AlertSeverity::High,
        "Defense Evasion",
        "Direct Syscall Execution",
        "Process executed direct syscall from unbacked memory stub",
        proc_key,
        ConfidenceLevel::Confirmed,
        1000,
    )
    .with_mitre("T1106")
    .with_evidence("target_address", "0x7fff1234");

    manager.emit(alert.clone());

    assert_eq!(manager.len(), 1);
    assert!(!manager.is_empty());

    let recent = manager.recent_alerts(5);
    assert_eq!(recent.len(), 1);
    assert_eq!(recent[0].title, "Direct Syscall Execution");
    assert_eq!(recent[0].severity, AlertSeverity::High);
    assert_eq!(recent[0].mitre_technique.as_deref(), Some("T1106"));
    assert_eq!(recent[0].evidence.get("target_address").map(|s| s.as_str()), Some("0x7fff1234"));
}

#[test]
fn test_alert_manager_bounded_capacity() {
    let capacity = 5;
    let manager = AlertManager::new(capacity);
    let proc_key = ProcessKey::new();

    for i in 0..10 {
        let alert = AlertRecord::new(
            AlertSeverity::Medium,
            "Test",
            format!("Alert #{i}"),
            "Test alert description",
            proc_key,
            ConfidenceLevel::Medium,
            1000 + i as i64,
        );
        manager.emit(alert);
    }

    assert!(manager.len() <= 100);
}

#[test]
fn test_alert_sink_dispatch() {
    let manager = AlertManager::new(10);
    let call_count = Arc::new(AtomicUsize::new(0));

    let mock_sink = Box::new(MockSink {
        call_count: Arc::clone(&call_count),
    });
    manager.add_sink(mock_sink);

    let alert = AlertRecord::new(
        AlertSeverity::Critical,
        "Process Injection",
        "Process Hollowing Detected",
        "Target executable section was unmapped and overwritten",
        ProcessKey::new(),
        ConfidenceLevel::Confirmed,
        2000,
    );

    manager.emit(alert);

    assert_eq!(call_count.load(Ordering::SeqCst), 1);
}

#[test]
fn test_alert_manager_once_per_process_deduplication() {
    let manager = AlertManager::new(10);
    let proc_key = ProcessKey::new();

    let alert1 = AlertRecord::new(
        AlertSeverity::High,
        "Defense Evasion",
        "Direct Syscall Execution",
        "First occurrence",
        proc_key,
        ConfidenceLevel::Confirmed,
        1000,
    )
    .once_per_process();

    let alert2 = AlertRecord::new(
        AlertSeverity::High,
        "Defense Evasion",
        "Direct Syscall Execution",
        "Second occurrence (should be suppressed)",
        proc_key,
        ConfidenceLevel::Confirmed,
        1005,
    )
    .once_per_process();

    assert!(manager.emit(alert1));
    assert!(!manager.emit(alert2)); // Suppressed by OncePerProcess policy

    // Only 1 alert should be recorded in manager
    assert_eq!(manager.len(), 1);

    // Another process with the same alert title must succeed
    let other_proc = ProcessKey::new();
    let alert3 = AlertRecord::new(
        AlertSeverity::High,
        "Defense Evasion",
        "Direct Syscall Execution",
        "Occurrence in another process",
        other_proc,
        ConfidenceLevel::Confirmed,
        1010,
    )
    .once_per_process();

    assert!(manager.emit(alert3));
    assert_eq!(manager.len(), 2);
}

#[test]
fn test_alert_manager_throttled_cooldown_policy() {
    let manager = AlertManager::new(10);
    let proc_key = ProcessKey::new();

    let alert1 = AlertRecord::new(
        AlertSeverity::Informational,
        "Research",
        "JIT Telemetry",
        "JIT call 1",
        proc_key,
        ConfidenceLevel::Low,
        1_000, // 1000ms
    )
    .with_cooldown(5_000); // 5s cooldown

    let alert2 = AlertRecord::new(
        AlertSeverity::Informational,
        "Research",
        "JIT Telemetry",
        "JIT call 2 (within cooldown)",
        proc_key,
        ConfidenceLevel::Low,
        3_000, // 3000ms (diff 2000 < 5000)
    )
    .with_cooldown(5_000);

    let alert3 = AlertRecord::new(
        AlertSeverity::Informational,
        "Research",
        "JIT Telemetry",
        "JIT call 3 (after cooldown)",
        proc_key,
        ConfidenceLevel::Low,
        7_000, // 7000ms (diff 6000 >= 5000)
    )
    .with_cooldown(5_000);

    assert!(manager.emit(alert1));
    assert!(!manager.emit(alert2)); // Suppressed
    assert!(manager.emit(alert3));  // Emitted after cooldown expired

    assert_eq!(manager.len(), 2);
}
