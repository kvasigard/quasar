//! Unified analytical detection sink evaluating pipeline events against compiled Rhai rules.
//!
//! Replaces specialized domain sinks by acting as the single detection subscriber attached
//! to [`EventDispatcher`](crate::pipeline::EventDispatcher). Enriches raw incoming events,
//! executes the dynamic [`RuleEngine`](crate::rules::RuleEngine), and routes alerts to the configured emitter.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use shared::ring_buffer::LsassAccessEvent;
use uuid::Uuid;

use crate::alerts::{Alert, AlertEmitter, AlertSeverity, ConsoleEmitter, MitreAttack};
use crate::enrichment::lsass::enrich_lsass_access;
use crate::pipeline::EventListener;
use crate::rules::{RuleEngine, RuleVerdict};

/// Unified analytical detection sink.
pub struct DetectionSink {
    rule_engine: Option<Arc<RuleEngine>>,
    emitter: Arc<dyn AlertEmitter>,
}

impl DetectionSink {
    /// Constructs a `DetectionSink` with custom rule engine and emitter implementations.
    ///
    /// # Arguments
    ///
    /// * `rule_engine` - Optional shared reference to the [`RuleEngine`].
    /// * `emitter` - Shared reference to the alert destination.
    ///
    /// # Returns
    ///
    /// An initialized [`DetectionSink`] instance.
    pub fn new(rule_engine: Option<Arc<RuleEngine>>, emitter: Arc<dyn AlertEmitter>) -> Self {
        Self {
            rule_engine,
            emitter,
        }
    }
}

impl Default for DetectionSink {
    fn default() -> Self {
        Self {
            rule_engine: None,
            emitter: Arc::new(ConsoleEmitter::new()),
        }
    }
}

impl EventListener for DetectionSink {
    /// Handles intercepted kernel Object Manager access events targeting LSASS.
    ///
    /// 1. Enriches the raw event with process tree lineage, user SID, and access rights.
    /// 2. Evaluates the enriched snapshot against the dynamic Rhai rule engine.
    /// 3. If rules pass or are disabled, falls back to a baseline heuristic checking for
    ///    dump-sensitive access rights (`PROCESS_VM_READ`, `PROCESS_VM_WRITE`, `PROCESS_DUP_HANDLE`).
    ///
    /// # Arguments
    ///
    /// * `raw_event` - Kernel telemetry payload received from the Singularity ring buffer.
    fn on_lsass_access(&self, raw_event: &LsassAccessEvent) {
        let enriched = enrich_lsass_access(raw_event);
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        if let Some(engine) = &self.rule_engine {
            match engine.evaluate(&enriched) {
                RuleVerdict::Suppress { reason, .. } => {
                    log::debug!(
                        target: "detection_sink",
                        "[SUPPRESS] PID {} ({}) suppressed: {}",
                        enriched.actor.pid,
                        enriched.actor.name,
                        reason
                    );
                    return;
                }
                RuleVerdict::Alert {
                    severity,
                    title,
                    description,
                    mitre_tactic,
                    mitre_technique,
                    rule_name,
                } => {
                    let (technique_id, subtechnique_id) = match mitre_technique.split_once('.') {
                        Some((base, _)) => (base.to_string(), Some(mitre_technique)),
                        None => (mitre_technique, None),
                    };

                    let alert = Alert {
                        id: Uuid::new_v4(),
                        timestamp: now_ms,
                        severity,
                        title,
                        description,
                        mitre: MitreAttack {
                            tactic: mitre_tactic,
                            technique_id,
                            subtechnique_id,
                            technique_name: "OS Credential Dumping: LSASS Memory".to_string(),
                        },
                        actor: enriched.actor,
                        target: enriched.target,
                        operation: enriched.operation,
                        mitigation: enriched.mitigation,
                        rule_name,
                        tags: HashMap::new(),
                    };

                    self.emitter.emit(&alert);
                    return;
                }
                RuleVerdict::Pass => {
                    // Fall through to baseline heuristic check below
                }
            }
        }

        // Baseline fallback: if rules passed or are disabled, flag access requests containing
        // rights commonly abused for memory dumping:
        // - PROCESS_VM_READ (0x0010): Reading LSASS virtual memory
        // - PROCESS_VM_WRITE (0x0020): Modifying LSASS memory
        // - PROCESS_DUP_HANDLE (0x0040): Duplicating existing privileged handles
        const PROCESS_VM_READ: u32 = 0x0010;
        const PROCESS_VM_WRITE: u32 = 0x0020;
        const PROCESS_DUP_HANDLE: u32 = 0x0040;
        const DUMP_SENSITIVE_RIGHTS: u32 = PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_DUP_HANDLE;

        let requests_dump_rights = (raw_event.desired_access & DUMP_SENSITIVE_RIGHTS) != 0;

        if requests_dump_rights {
            let severity = if enriched.raw.signature_level < 8 {
                AlertSeverity::High
            } else {
                AlertSeverity::Medium
            };

            let alert = Alert {
                id: Uuid::new_v4(),
                timestamp: now_ms,
                severity,
                title: format!(
                    "Suspicious LSASS Handle [{}]",
                    enriched.operation.operation_type
                ),
                description: format!(
                    "Process {} (PID {}) requested sensitive rights ({:#010X}) targeting LSASS. Mitigation status: {}.",
                    enriched.actor.name,
                    raw_event.source_pid,
                    raw_event.desired_access,
                    enriched.mitigation
                ),
                mitre: MitreAttack::default(),
                actor: enriched.actor,
                target: enriched.target,
                operation: enriched.operation,
                mitigation: enriched.mitigation,
                rule_name: Some("builtin_fallback_dump_rights".to_string()),
                tags: HashMap::new(),
            };

            self.emitter.emit(&alert);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct MockEmitter {
        emit_count: AtomicUsize,
    }

    impl AlertEmitter for MockEmitter {
        fn emit(&self, _alert: &Alert) {
            self.emit_count.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn test_detection_sink_fallback_heuristic() {
        let emitter = Arc::new(MockEmitter {
            emit_count: AtomicUsize::new(0),
        });

        let sink = DetectionSink::new(None, emitter.clone());

        // Desired access with PROCESS_VM_READ (0x0010)
        let event =
            LsassAccessEvent::new(5000, 816, 0x0010, 0x1000, 0x3000, 0, 0, 1, b"untrusted.exe");

        sink.on_lsass_access(&event);
        assert_eq!(emitter.emit_count.load(Ordering::SeqCst), 1);
    }
}
