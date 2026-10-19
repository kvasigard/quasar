//! Rhai type wrappers and scope bindings.
//!
//! Exposes strongly-typed representations of [`LsassAccessEvent`] and [`ActorContext`]
//! to the Rhai AST interpreter with zero serialization tax, along with convenience helpers.

use rhai::Engine;
use shared::ring_buffer::LsassAccessEvent;

use crate::alerts::{ActorContext, AlertSeverity, TargetContext};
use crate::rules::verdict::RuleVerdict;

/// Wrapper representing an intercepted event in Rhai.
///
/// Integer fields are cast to signed `i64` because Rhai's default integer type (`INT`)
/// is signed 64-bit, enabling natural comparison expressions in scripts without typecasting.
#[derive(Debug, Clone)]
pub struct RhaiEvent {
    pub source_pid: i64,
    pub target_pid: i64,
    pub desired_access: i64,
    pub granted_access: i64,
    pub signature_level: i64,
    pub protection: i64,
    pub integrity_level: i64,
    pub operation: i64,
    pub short_name: String,
    pub is_mitigated: bool,
}

impl RhaiEvent {
    /// Constructs a `RhaiEvent` snapshot from a raw kernel [`LsassAccessEvent`].
    ///
    /// # Arguments
    ///
    /// * `event` - Reference to the raw kernel event payload.
    ///
    /// # Returns
    ///
    /// A `RhaiEvent` ready for scope injection.
    pub fn from_kernel_event(event: &LsassAccessEvent) -> Self {
        let raw_name = String::from_utf8_lossy(&event.short_name);
        let short_name = raw_name.trim_matches('\0').to_string();

        Self {
            source_pid: event.source_pid as i64,
            target_pid: event.target_pid as i64,
            desired_access: event.desired_access as i64,
            granted_access: event.granted_access as i64,
            signature_level: event.signature_level as i64,
            protection: event.protection as i64,
            integrity_level: event.integrity_level as i64,
            operation: event.operation as i64,
            short_name,
            is_mitigated: event.desired_access != event.granted_access,
        }
    }
}

/// Wrapper representing process and lineage context in Rhai.
#[derive(Debug, Clone)]
pub struct RhaiActor {
    pub pid: i64,
    pub name: String,
    pub image_path: String,
    pub command_line: String,
    pub user_sid: String,
    pub parent_pid: i64,
    pub parent_name: String,
    pub ancestry: Vec<String>,
}

impl RhaiActor {
    /// Constructs a `RhaiActor` snapshot from an [`ActorContext`].
    ///
    /// # Arguments
    ///
    /// * `ctx` - Resolved actor context snapshot.
    ///
    /// # Returns
    ///
    /// A `RhaiActor` ready for scope injection.
    pub fn from_context(ctx: &ActorContext) -> Self {
        Self {
            pid: ctx.pid as i64,
            name: ctx.name.clone(),
            image_path: ctx.image_path.clone(),
            command_line: ctx.command_line.clone(),
            user_sid: ctx.user_sid.clone(),
            parent_pid: ctx.parent_pid as i64,
            parent_name: ctx.parent_name.clone(),
            ancestry: ctx.ancestry.clone(),
        }
    }

    /// Checks if any ancestor process in the execution tree matches `name` (case-insensitive).
    ///
    /// Because `ancestry` is ordered chronologically from root to actor (`[root, ..., parent, actor]`),
    /// the last element is the actor itself and is excluded from ancestor matching.
    ///
    /// # Arguments
    ///
    /// * `name` - Substring or full binary name to look for in the ancestor lineage.
    ///
    /// # Returns
    ///
    /// `true` if any parent/ancestor contains the target name; otherwise `false`.
    pub fn has_ancestor(&self, name: &str) -> bool {
        let ancestor_slice = if self.ancestry.len() > 1 {
            &self.ancestry[..self.ancestry.len() - 1]
        } else {
            &[]
        };
        let needle = name.to_lowercase();
        ancestor_slice
            .iter()
            .any(|ancestor| ancestor.to_lowercase().contains(&needle))
    }
}

/// Parses a human-readable severity string into an [`AlertSeverity`] enum variant.
pub fn parse_severity(severity: &str) -> AlertSeverity {
    match severity.to_lowercase().as_str() {
        "critical" => AlertSeverity::Critical,
        "high" => AlertSeverity::High,
        "medium" => AlertSeverity::Medium,
        "low" => AlertSeverity::Low,
        _ => AlertSeverity::Informational,
    }
}

/// Wrapper representing the target entity in Rhai.
#[derive(Debug, Clone)]
pub struct RhaiTarget {
    pub pid: i64,
    pub name: String,
    pub entity_type: String,
}

impl RhaiTarget {
    /// Constructs a `RhaiTarget` snapshot from a [`TargetContext`].
    ///
    /// # Arguments
    ///
    /// * `ctx` - Resolved target context snapshot.
    ///
    /// # Returns
    ///
    /// A `RhaiTarget` ready for scope injection.
    pub fn from_context(ctx: &TargetContext) -> Self {
        Self {
            pid: ctx.pid as i64,
            name: ctx.name.clone(),
            entity_type: ctx.entity_type.clone(),
        }
    }
}

/// Registers all custom types, getters, and helper functions into the Rhai engine.
pub fn register_bindings(engine: &mut Engine) {
    // 1. Register RhaiEvent
    engine.register_type_with_name::<RhaiEvent>("Event");
    engine.register_get("source_pid", |e: &mut RhaiEvent| e.source_pid);
    engine.register_get("target_pid", |e: &mut RhaiEvent| e.target_pid);
    engine.register_get("desired_access", |e: &mut RhaiEvent| e.desired_access);
    engine.register_get("granted_access", |e: &mut RhaiEvent| e.granted_access);
    engine.register_get("signature_level", |e: &mut RhaiEvent| e.signature_level);
    engine.register_get("protection", |e: &mut RhaiEvent| e.protection);
    engine.register_get("integrity_level", |e: &mut RhaiEvent| e.integrity_level);
    engine.register_get("operation", |e: &mut RhaiEvent| e.operation);
    engine.register_get("short_name", |e: &mut RhaiEvent| e.short_name.clone());
    engine.register_get("is_mitigated", |e: &mut RhaiEvent| e.is_mitigated);
    engine.register_fn("to_hex", |val: i64| format!("{val:#010X}"));

    // 2. Register RhaiActor
    engine.register_type_with_name::<RhaiActor>("Actor");
    engine.register_get("pid", |a: &mut RhaiActor| a.pid);
    engine.register_get("name", |a: &mut RhaiActor| a.name.clone());
    engine.register_get("image_path", |a: &mut RhaiActor| a.image_path.clone());
    engine.register_get("command_line", |a: &mut RhaiActor| a.command_line.clone());
    engine.register_get("user_sid", |a: &mut RhaiActor| a.user_sid.clone());
    engine.register_get("parent_pid", |a: &mut RhaiActor| a.parent_pid);
    engine.register_get("parent_name", |a: &mut RhaiActor| a.parent_name.clone());
    engine.register_fn("has_ancestor", |a: &mut RhaiActor, name: &str| {
        a.has_ancestor(name)
    });

    // 3. Register RhaiTarget
    engine.register_type_with_name::<RhaiTarget>("Target");
    engine.register_get("pid", |t: &mut RhaiTarget| t.pid);
    engine.register_get("name", |t: &mut RhaiTarget| t.name.clone());
    engine.register_get("entity_type", |t: &mut RhaiTarget| t.entity_type.clone());

    // 4. Register RuleVerdict
    engine.register_type_with_name::<RuleVerdict>("Verdict");

    // 5. Register Verdict Constructors
    engine.register_fn(
        "suppress",
        |reason: &str, cooldown_seconds: i64| -> RuleVerdict {
            RuleVerdict::Suppress {
                reason: reason.to_string(),
                cooldown_seconds: cooldown_seconds.max(0) as u32,
            }
        },
    );

    // 2-argument `alert(title, description)` constructor that inherits severity, tactic, and
    // technique from the rule's `fn rule_info()` metadata during `evaluate_rule`.
    engine.register_fn("alert", |title: &str, description: &str| -> RuleVerdict {
        RuleVerdict::Alert {
            severity: AlertSeverity::Informational,
            title: title.to_string(),
            description: description.to_string(),
            mitre_tactic: String::new(),
            mitre_technique: String::new(),
            rule_name: None,
        }
    });

    // 5-argument `alert(severity, title, description, mitre_tactic, mitre_technique)` override.
    engine.register_fn(
        "alert",
        |severity: &str,
         title: &str,
         description: &str,
         mitre_tactic: &str,
         mitre_technique: &str|
         -> RuleVerdict {
            RuleVerdict::Alert {
                severity: parse_severity(severity),
                title: title.to_string(),
                description: description.to_string(),
                mitre_tactic: mitre_tactic.to_string(),
                mitre_technique: mitre_technique.to_string(),
                rule_name: None,
            }
        },
    );

    engine.register_fn("pass", || -> RuleVerdict { RuleVerdict::Pass });

    // 5. Utility string and bitwise helpers
    engine.register_fn("starts_with_ic", |s: &str, prefix: &str| -> bool {
        s.to_lowercase().starts_with(&prefix.to_lowercase())
    });

    engine.register_fn("contains_ic", |s: &str, needle: &str| -> bool {
        s.to_lowercase().contains(&needle.to_lowercase())
    });

    engine.register_fn("ends_with_ic", |s: &str, suffix: &str| -> bool {
        s.to_lowercase().ends_with(&suffix.to_lowercase())
    });

    engine.register_fn("has_mask", |mask: i64, bit: i64| -> bool {
        (mask & bit) == bit
    });
}
