//! Rule evaluation verdict contract between Rhai scripts and Pulsar analytical sinks.

use crate::alerts::AlertSeverity;

/// The outcome of evaluating an event against Rhai rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleVerdict {
    /// Suppress candidate alert.
    ///
    /// If `cooldown_seconds == 0`, the suppression is valid for the entire lifetime of this process instance.
    /// If `cooldown_seconds > 0`, the suppression expires after $N$ seconds.
    Suppress {
        /// Human-readable rationale for why this operation was whitelisted.
        reason: String,
        /// Cooldown duration in seconds (0 = process lifetime).
        cooldown_seconds: u32,
    },

    /// Raise a confirmed security alert with triage metadata.
    Alert {
        /// Triage severity rating.
        severity: AlertSeverity,
        /// Short summary title.
        title: String,
        /// Detailed description and technical context.
        description: String,
        /// MITRE ATT&CK Tactic name.
        mitre_tactic: String,
        /// MITRE ATT&CK Technique or Sub-technique ID (e.g. "T1003.001").
        mitre_technique: String,
        /// Rule name or path that triggered this alert.
        rule_name: Option<String>,
    },

    /// The rule does not match the event. Continue evaluating subsequent rules in the chain.
    Pass,
}

impl RuleVerdict {
    /// Returns `true` if this verdict is [`RuleVerdict::Suppress`].
    #[inline]
    pub fn is_suppress(&self) -> bool {
        matches!(self, Self::Suppress { .. })
    }

    /// Returns `true` if this verdict is [`RuleVerdict::Alert`].
    #[inline]
    pub fn is_alert(&self) -> bool {
        matches!(self, Self::Alert { .. })
    }

    /// Returns `true` if this verdict is [`RuleVerdict::Pass`].
    #[inline]
    pub fn is_pass(&self) -> bool {
        matches!(self, Self::Pass)
    }
}
