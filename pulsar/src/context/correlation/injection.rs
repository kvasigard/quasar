//! Stateful process injection correlator and sequence state machine.

use std::sync::Arc;
use dashmap::DashMap;

use crate::context::identity::{EntityId, ProcessKey};
use crate::context::models::interaction::{
    ConfidenceLevel, ExecutionTrigger, InjectionDetails, InjectionTechnique, InteractionKind,
    InteractionRecord,
};
use crate::context::registries::{InteractionRegistry, ProcessTree};

/// State of an in-flight cross-process injection session between actor and target.
#[derive(Debug, Clone)]
pub struct InFlightInjection {
    /// Actor process performing injection actions.
    pub actor_key: ProcessKey,
    /// Target process receiving injected code.
    pub target_key: ProcessKey,
    /// Timestamp when first stage was observed.
    pub session_start: i64,
    /// Timestamp of most recent activity.
    pub last_updated: i64,
    /// Whether an open handle with write permissions was recorded.
    pub has_target_handle: bool,
    /// Allocated virtual memory base address.
    pub allocated_base: Option<u64>,
    /// Number of bytes allocated.
    pub allocated_size: Option<usize>,
    /// Whether memory write occurred.
    pub memory_written: bool,
    /// Total sequential attack stages observed.
    pub stages: u8,
}

/// Correlator tracking multi-step injection sequences across time.
pub struct InjectionCorrelator {
    /// Active in-flight sessions: `(ActorKey, TargetKey) -> InFlightInjection`.
    sessions: DashMap<(ProcessKey, ProcessKey), InFlightInjection>,
    /// Session timeout in milliseconds (default: 30 seconds = 30,000 ms).
    session_timeout_ms: i64,
}

impl InjectionCorrelator {
    /// Creates a new `InjectionCorrelator`.
    ///
    /// # Returns
    ///
    /// An initialized [`InjectionCorrelator`].
    pub fn new() -> Self {
        Self {
            sessions: DashMap::new(),
            session_timeout_ms: 30_000,
        }
    }

    /// Records that an actor opened a write handle to a target process.
    ///
    /// # Arguments
    ///
    /// * `actor_key` - Synthetic key of the actor process.
    /// * `target_key` - Synthetic key of the target process.
    /// * `timestamp` - Operation timestamp.
    #[tracing::instrument(name = "correlate_injection_handle_open", skip(self), level = "debug")]
    pub fn on_target_handle_opened(
        &self,
        actor_key: ProcessKey,
        target_key: ProcessKey,
        timestamp: i64,
    ) {
        if actor_key == target_key {
            return; // Self-opens are not cross-process injection
        }

        let mut session = self
            .sessions
            .entry((actor_key, target_key))
            .or_insert_with(|| InFlightInjection {
                actor_key,
                target_key,
                session_start: timestamp,
                last_updated: timestamp,
                has_target_handle: true,
                allocated_base: None,
                allocated_size: None,
                memory_written: false,
                stages: 1,
            });

        session.has_target_handle = true;
        session.last_updated = timestamp;
    }

    /// Records that an actor allocated memory (e.g. PAGE_EXECUTE_READWRITE) in a target process.
    ///
    /// # Arguments
    ///
    /// * `actor_key` - Synthetic key of the actor process.
    /// * `target_key` - Synthetic key of the target process.
    /// * `base_address` - Base address of allocated memory.
    /// * `size` - Size of allocation.
    /// * `timestamp` - Operation timestamp.
    #[tracing::instrument(name = "correlate_injection_memory_alloc", skip(self), level = "debug")]
    pub fn on_remote_memory_alloc(
        &self,
        actor_key: ProcessKey,
        target_key: ProcessKey,
        base_address: u64,
        size: usize,
        timestamp: i64,
    ) {
        if actor_key == target_key {
            return;
        }

        let mut session = self
            .sessions
            .entry((actor_key, target_key))
            .or_insert_with(|| InFlightInjection {
                actor_key,
                target_key,
                session_start: timestamp,
                last_updated: timestamp,
                has_target_handle: false,
                allocated_base: Some(base_address),
                allocated_size: Some(size),
                memory_written: false,
                stages: 1,
            });

        session.allocated_base = Some(base_address);
        session.allocated_size = Some(size);
        session.stages = session.stages.saturating_add(1);
        session.last_updated = timestamp;
    }

    /// Records that an actor wrote memory to a target process.
    ///
    /// # Arguments
    ///
    /// * `actor_key` - Synthetic key of the actor process.
    /// * `target_key` - Synthetic key of the target process.
    /// * `base_address` - Base address written to.
    /// * `timestamp` - Operation timestamp.
    #[tracing::instrument(name = "correlate_injection_memory_write", skip(self), level = "debug")]
    pub fn on_remote_memory_write(
        &self,
        actor_key: ProcessKey,
        target_key: ProcessKey,
        base_address: u64,
        timestamp: i64,
    ) {
        if actor_key == target_key {
            return;
        }

        if let Some(mut session) = self.sessions.get_mut(&(actor_key, target_key)) {
            session.memory_written = true;
            session.stages = session.stages.saturating_add(1);
            session.last_updated = timestamp;
            if session.allocated_base.is_none() {
                session.allocated_base = Some(base_address);
            }
        }
    }

    /// Records that an actor created a remote execution trigger (Remote Thread, APC, SetThreadContext) in target.
    /// Emits a high-confidence `InteractionRecord` to the interaction registry.
    ///
    /// # Arguments
    ///
    /// * `actor_key` - Synthetic key of the actor process.
    /// * `target_key` - Synthetic key of the target process.
    /// * `trigger` - Execution trigger type.
    /// * `technique` - Inferred technique.
    /// * `timestamp` - Operation timestamp.
    /// * `interactions` - Reference to the interaction registry.
    /// * `processes` - Reference to the process tree arena.
    ///
    /// # Returns
    ///
    /// `Some(Arc<InteractionRecord>)` if a valid cross-process injection was confirmed.
    #[allow(clippy::too_many_arguments)]
    #[tracing::instrument(name = "correlate_injection_execution_trigger", skip(self, interactions, processes), level = "debug")]
    pub fn on_remote_execution(
        &self,
        actor_key: ProcessKey,
        target_key: ProcessKey,
        trigger: ExecutionTrigger,
        technique: InjectionTechnique,
        timestamp: i64,
        interactions: &InteractionRegistry,
        processes: &ProcessTree,
    ) -> Option<Arc<InteractionRecord>> {
        if actor_key == target_key {
            return None;
        }

        let session = self
            .sessions
            .remove(&(actor_key, target_key))
            .map(|(_, s)| s);

        let stages = session.as_ref().map_or(1, |s| s.stages.saturating_add(1));
        let allocated_base = session.as_ref().and_then(|s| s.allocated_base);
        let allocated_size = session.as_ref().and_then(|s| s.allocated_size);

        let confidence = if stages >= 3 {
            ConfidenceLevel::Confirmed
        } else if stages >= 2 {
            ConfidenceLevel::High
        } else {
            ConfidenceLevel::Medium
        };

        let details = InjectionDetails {
            technique,
            target_base_address: allocated_base,
            allocated_size,
            execution_trigger: Some(trigger),
            stages_observed: stages,
        };

        let record = InteractionRecord::new(
            InteractionKind::ProcessInjection(details),
            EntityId::Process(actor_key),
            EntityId::Process(target_key),
            timestamp,
            confidence,
            format!("Process injection ({technique:?}) via {trigger:?} observed across {stages} stages"),
        );

        // Pin both processes to preserve forensics for detection
        if let Some(actor) = processes.get_by_key(actor_key) {
            actor.pin();
        }
        if let Some(target) = processes.get_by_key(target_key) {
            target.pin();
        }

        Some(interactions.record(record))
    }

    /// Prunes stale in-flight sessions that never completed within the timeout window.
    ///
    /// # Arguments
    ///
    /// * `now` - Current timestamp.
    ///
    /// # Returns
    ///
    /// Number of pruned sessions.
    pub fn prune_stale_sessions(&self, now: i64) -> usize {
        let mut to_remove = Vec::new();
        for entry in self.sessions.iter() {
            if now - entry.value().last_updated > self.session_timeout_ms {
                to_remove.push(*entry.key());
            }
        }

        let count = to_remove.len();
        for key in to_remove {
            self.sessions.remove(&key);
        }
        count
    }
}

impl Default for InjectionCorrelator {
    fn default() -> Self {
        Self::new()
    }
}
