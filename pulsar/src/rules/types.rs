//! Rule categorization, stages, metadata models, and scriptable telemetry abstractions.
//!
//! Provides the core data types governing rule classification, multi-dimensional
//! indexing by `(EventType, RuleStage)`, and the [`ScriptableEvent`] trait decoupling
//! the Rhai evaluation pipeline from concrete kernel telemetry formats.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rhai::{Scope, AST};
use serde::{Deserialize, Serialize};

use crate::alerts::AlertSeverity;

/// Telemetry event categories monitored by detection rules.
///
/// Only currently active and implemented telemetry event types are defined here;
/// future telemetry sources will be introduced alongside their corresponding engine implementations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EventType {
    /// Kernel Object Manager handle pre-operation targeting a process.
    ObProcessHandle,
}

/// Execution phase for a compiled rule within the evaluation pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RuleStage {
    /// Whitelist and false-positive suppression rules.
    Suppression,
    /// Behavioral anomaly and threat detection rules.
    Detection,
}

/// Static metadata parsed from a rule's `fn rule_info()` declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleMetadata {
    /// Human-readable rule identifier.
    pub name: String,
    /// Telemetry event type subscribed to by this rule.
    pub event_type: EventType,
    /// Pipeline evaluation phase.
    pub stage: RuleStage,
    /// Default triage severity if alert() does not override.
    pub severity: Option<AlertSeverity>,
    /// Associated MITRE ATT&CK tactic.
    pub mitre_tactic: Option<String>,
    /// Associated MITRE ATT&CK technique ID.
    pub mitre_technique: Option<String>,
}

/// In-memory representation of a compiled rule script.
#[derive(Debug, Clone)]
pub struct CompiledRule {
    /// Extracted declarative metadata.
    pub metadata: RuleMetadata,
    /// Filesystem origin path for logging and hot-reloading diagnostics.
    pub file_path: PathBuf,
    /// Pre-compiled immutable AST.
    pub ast: Arc<AST>,
}

/// Fast lookup index organizing compiled rules by event type and execution phase.
#[derive(Debug, Default, Clone)]
pub struct RuleIndex {
    rules: HashMap<(EventType, RuleStage), Vec<CompiledRule>>,
    total_count: usize,
}

impl RuleIndex {
    /// Constructs an empty `RuleIndex`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts a compiled rule into the index under its declared `(EventType, RuleStage)`.
    ///
    /// # Arguments
    ///
    /// * `rule` - The compiled rule to register in the index.
    pub fn insert(&mut self, rule: CompiledRule) {
        let key = (rule.metadata.event_type, rule.metadata.stage);
        self.rules.entry(key).or_default().push(rule);
        self.total_count += 1;
    }

    /// Inserts or replaces a compiled rule associated with a specific filesystem path.
    ///
    /// Evicts any existing rule compiled from the same file path before inserting the new
    /// version, ensuring atomic in-place updates during hot-reloads.
    ///
    /// # Arguments
    ///
    /// * `rule` - The updated compiled rule instance.
    pub fn upsert(&mut self, rule: CompiledRule) {
        self.remove_by_path(&rule.file_path);
        self.insert(rule);
    }

    /// Removes all rules originated from the specified filesystem path.
    ///
    /// Used during incremental hot-reloading when a rule file is deleted from disk.
    ///
    /// # Arguments
    ///
    /// * `path` - Filesystem path of the deleted `.rhai` script.
    ///
    /// # Returns
    ///
    /// `true` if one or more rules were removed from the index; otherwise `false`.
    pub fn remove_by_path(&mut self, path: &Path) -> bool {
        let mut removed = false;
        for rules in self.rules.values_mut() {
            let before = rules.len();
            rules.retain(|r| r.file_path != path);
            let diff = before - rules.len();
            if diff > 0 {
                self.total_count -= diff;
                removed = true;
            }
        }
        removed
    }

    /// Retrieves an immutable slice of compiled rules registered for the given event type and stage.
    ///
    /// # Arguments
    ///
    /// * `event_type` - Telemetry event type filter.
    /// * `stage` - Rule execution phase (Suppression or Detection).
    ///
    /// # Returns
    ///
    /// Slice of matching compiled rules, or an empty slice if no rules are registered for the pair.
    pub fn get(&self, event_type: EventType, stage: RuleStage) -> &[CompiledRule] {
        self.rules
            .get(&(event_type, stage))
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Returns the total number of rules registered across all event types and stages.
    pub fn total_count(&self) -> usize {
        self.total_count
    }
}

/// Trait implemented by enriched telemetry events to enable uniform evaluation in the Rhai engine.
///
/// # Example Implementation
///
/// ```rust,ignore
/// impl ScriptableEvent for EnrichedLsassAccessEvent {
///     fn event_type(&self) -> EventType {
///         EventType::ObProcessHandle
///     }
///
///     fn suppression_key(&self) -> Option<(u32, u32)> {
///         // Cache by (PID, desired_access) so repetitive polling (e.g. Taskmgr) bypasses Rhai in < 5ns
///         Some((self.raw.source_pid, self.raw.desired_access))
///     }
///
///     fn populate_scope(&self, scope: &mut Scope) {
///         scope.push("event", RhaiEvent::from_kernel_event(&self.raw));
///         scope.push("actor", RhaiActor::from_context(&self.actor));
///         scope.push("target", RhaiTarget::from_context(&self.target));
///     }
/// }
/// ```
pub trait ScriptableEvent {
    /// Target event category. The engine uses this to fetch only the rules subscribed to this exact event type.
    fn event_type(&self) -> EventType;

    /// Optional `(caller_pid, discriminator)` composite key for rapid in-memory suppression caching.
    ///
    /// Useful for high-frequency events (like handle queries) to return cached whitelists in < 5ns.
    /// Return `None` if the event is irregular or should always evaluate rules directly.
    fn suppression_key(&self) -> Option<(u32, u32)> {
        None
    }

    /// Injects event context into the Rhai script scope (e.g. `event`, `actor`, `target`).
    ///
    /// Called before evaluating each rule to provide script bindings without unnecessary heap allocations.
    ///
    /// # Arguments
    ///
    /// * `scope` - Mutable reference to the local Rhai execution scope.
    fn populate_scope(&self, scope: &mut Scope);
}
