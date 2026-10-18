//! Analytical sink tracking process lifecycle events to maintain live system context.
//!
//! Feeds ETW process creation, rundown, and termination events into [`SystemState`]
//! and notifies [`RuleEngine`] to prune stale suppression cache entries on process exit.

use std::sync::Arc;

use crate::model::events::process::{ProcessEvent, ProcessEventKind};
use crate::model::types::ExitStatus;
use crate::model::ProcessNode;
use crate::pipeline::EventListener;
use crate::rules::RuleEngine;
use crate::state::system_state;

/// Context sink that maintains the live process tree in `SystemState`.
pub struct ProcessContextSink {
    rule_engine: Option<Arc<RuleEngine>>,
}

impl ProcessContextSink {
    /// Constructs a new `ProcessContextSink` linked to an optional [`RuleEngine`].
    ///
    /// # Arguments
    ///
    /// * `rule_engine` - Optional shared reference to the [`RuleEngine`] notified on process exits.
    ///
    /// # Returns
    ///
    /// An initialized [`ProcessContextSink`].
    pub fn new(rule_engine: Option<Arc<RuleEngine>>) -> Self {
        Self { rule_engine }
    }
}

impl EventListener for ProcessContextSink {
    fn on_process(&self, event: &ProcessEvent) {
        match event.kind {
            ProcessEventKind::Start | ProcessEventKind::DCStart => {
                match ProcessNode::try_from(event) {
                    Ok(node) => {
                        let pid = node.key.pid;
                        if let Err(err) = system_state().on_process_start(node) {
                            log::trace!(
                                target: "context_sink",
                                "Process start ingestion skipped for PID {}: {}",
                                pid,
                                err
                            );
                        }
                    }
                    Err(err) => {
                        log::trace!(
                            target: "context_sink",
                            "Failed to construct ProcessNode from ProcessEvent: {}",
                            err
                        );
                    }
                }
            }
            ProcessEventKind::End | ProcessEventKind::Defunct => {
                let exit_status = event.exit_status.unwrap_or(ExitStatus::Success);
                if let Err(err) = system_state().on_process_exit(event.process_id, event.timestamp, exit_status) {
                    log::trace!(
                        target: "context_sink",
                        "Process exit untracked for PID {:?}: {}",
                        event.process_id,
                        err
                    );
                }

                // Prune suppression cache to avoid PID recycling collision bugs
                if let Some(engine) = &self.rule_engine {
                    engine.prune_process(event.process_id.0);
                }
            }
            ProcessEventKind::DCEnd => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::security::Sid;
    use crate::model::types::{ProcessId, SessionId, UniqueProcessKey};

    #[test]
    fn test_process_lifecycle_sink_updates_state() {
        let engine = Arc::new(RuleEngine::empty());
        let sink = ProcessContextSink::new(Some(Arc::clone(&engine)));

        let start_event = ProcessEvent {
            timestamp: 1000,
            emitter_pid: ProcessId(4),
            emitter_tid: 100,
            stack_trace: None,
            kind: ProcessEventKind::Start,
            unique_process_key: UniqueProcessKey(0x1234000),
            process_id: ProcessId(9999),
            parent_id: ProcessId(4000),
            session_id: SessionId(1),
            exit_status: None,
            user_sid: Sid("S-1-5-18".to_string()),
            image_file_name: "test_proc.exe".to_string(),
            command_line: "test_proc.exe --arg".to_string(),
        };

        sink.on_process(&start_event);

        // State should now have process key for PID 9999
        let key = system_state().resolve_process_key(ProcessId(9999), 1000);
        assert!(key.is_some(), "Process 9999 should exist in SystemState");

        // Populate suppression cache for PID 9999
        engine
            .cache()
            .insert(crate::rules::EventType::ObProcessHandle, 9999, 0x1410, 0);
        assert!(engine
            .cache()
            .is_suppressed(crate::rules::EventType::ObProcessHandle, 9999, 0x1410));

        // Terminate process
        let end_event = ProcessEvent {
            timestamp: 2000,
            emitter_pid: ProcessId(4),
            emitter_tid: 100,
            stack_trace: None,
            kind: ProcessEventKind::End,
            unique_process_key: UniqueProcessKey(0x1234000),
            process_id: ProcessId(9999),
            parent_id: ProcessId(4000),
            session_id: SessionId(1),
            exit_status: Some(ExitStatus::Success),
            user_sid: Sid("S-1-5-18".to_string()),
            image_file_name: "test_proc.exe".to_string(),
            command_line: "test_proc.exe --arg".to_string(),
        };

        sink.on_process(&end_event);

        // Cache should be pruned
        assert!(!engine
            .cache()
            .is_suppressed(crate::rules::EventType::ObProcessHandle, 9999, 0x1410));
    }
}
