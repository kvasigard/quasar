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
