//! Analytical alert domain models, severity taxonomy, emission policies, and evidence structures.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::context::identity::ProcessKey;
use crate::context::models::interaction::ConfidenceLevel;

/// Monotonically increasing synthetic identifier for an individual analytical alert.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AlertId(pub u64);

impl AlertId {
    /// Generates a globally unique, monotonically incrementing `AlertId`.
    ///
    /// # Returns
    ///
    /// A new, unique [`AlertId`].
    #[inline]
    pub fn new() -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(1);
        Self(COUNTER.fetch_add(1, Ordering::Relaxed))
    }

    /// Creates an `AlertId` from an explicit raw integer.
    #[inline]
    pub const fn from_raw(raw: u64) -> Self {
        Self(raw)
    }

    /// Returns the underlying raw 64-bit numeric value.
    #[inline]
    pub const fn as_u64(&self) -> u64 {
        self.0
    }
}

impl Default for AlertId {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for AlertId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Alert(#{})", self.0)
    }
}

/// Severity classification for detection alerts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum AlertSeverity {
    /// Informational telemetry anomaly with low operational impact.
    #[default]
    Informational,
    /// Low severity indicator (e.g. suspicious path access).
    Low,
    /// Medium severity heuristic (e.g. unbacked syscall stub).
    Medium,
    /// High severity confirmed evasion pattern (e.g. direct syscall bypass).
    High,
    /// Critical severity malicious execution (e.g. confirmed process hollowing).
    Critical,
}

impl AlertSeverity {
    /// Returns the standard uppercase string representation of the severity level.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Informational => "INFORMATIONAL",
            Self::Low => "LOW",
            Self::Medium => "MEDIUM",
            Self::High => "HIGH",
            Self::Critical => "CRITICAL",
        }
    }
}

impl std::fmt::Display for AlertSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Emission frequency and deduplication policy for analytical detection alerts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AlertEmissionPolicy {
    /// Emit every occurrence of the alert (default for critical attacks/injections).
    #[default]
    EveryEvent,
    /// Emit only once per unique process lifecycle (e.g. initial direct syscall evasion, JIT discovery).
    OncePerProcess,
    /// Emit at most once per process within a specified cooldown window in milliseconds.
    Throttled { cooldown_ms: u64 },
}

/// Structured record representing an analytical detection alert.
#[derive(Debug, Clone, PartialEq)]
pub struct AlertRecord {
    /// Unique synthetic alert identifier.
    pub id: AlertId,
    /// Timestamp when the alert was triggered (FILETIME 100ns intervals or UNIX epoch ms).
    pub timestamp: i64,
    /// Severity rating.
    pub severity: AlertSeverity,
    /// Analytical category (e.g. "Defense Evasion", "Process Injection").
    pub category: String,
    /// Short human-readable title.
    pub title: String,
    /// Detailed diagnostic description.
    pub description: String,
    /// Associated MITRE ATT&CK technique ID (e.g. "T1055.012", "T1106").
    pub mitre_technique: Option<String>,
    /// Originating / triggering process synthetic key.
    pub triggering_process: ProcessKey,
    /// Target process synthetic key if a cross-process interaction triggered the alert.
    pub target_process: Option<ProcessKey>,
    /// Confidence assessment of the detection heuristic.
    pub confidence: ConfidenceLevel,
    /// Emission deduplication and throttling policy.
    pub emission_policy: AlertEmissionPolicy,
    /// Contextual key-value evidence artifacts (e.g. RVA, module name, call stack).
    pub evidence: HashMap<String, String>,
}

impl AlertRecord {
    /// Creates a new `AlertRecord` with default empty evidence map.
    ///
    /// # Arguments
    ///
    /// * `severity` - Alert severity rating.
    /// * `category` - Behavioral category string.
    /// * `title` - Short descriptive title.
    /// * `description` - Technical diagnostic summary.
    /// * `triggering_process` - Originating process synthetic key.
    /// * `confidence` - Confidence level rating.
    /// * `timestamp` - Detection timestamp.
    ///
    /// # Returns
    ///
    /// An initialized [`AlertRecord`].
    pub fn new(
        severity: AlertSeverity,
        category: impl Into<String>,
        title: impl Into<String>,
        description: impl Into<String>,
        triggering_process: ProcessKey,
        confidence: ConfidenceLevel,
        timestamp: i64,
    ) -> Self {
        Self {
            id: AlertId::new(),
            timestamp,
            severity,
            category: category.into(),
            title: title.into(),
            description: description.into(),
            mitre_technique: None,
            triggering_process,
            target_process: None,
            confidence,
            emission_policy: AlertEmissionPolicy::EveryEvent,
            evidence: HashMap::new(),
        }
    }

    /// Attaches a MITRE ATT&CK technique reference.
    #[inline]
    pub fn with_mitre(mut self, technique: impl Into<String>) -> Self {
        self.mitre_technique = Some(technique.into());
        self
    }

    /// Attaches a target process reference.
    #[inline]
    pub fn with_target_process(mut self, target_key: ProcessKey) -> Self {
        self.target_process = Some(target_key);
        self
    }

    /// Configures this alert to fire only once per unique process lifecycle.
    #[inline]
    pub fn once_per_process(mut self) -> Self {
        self.emission_policy = AlertEmissionPolicy::OncePerProcess;
        self
    }

    /// Configures this alert to fire with a per-process throttling cooldown window.
    #[inline]
    pub fn with_cooldown(mut self, cooldown_ms: u64) -> Self {
        self.emission_policy = AlertEmissionPolicy::Throttled { cooldown_ms };
        self
    }

    /// Explicitly sets the alert emission policy.
    #[inline]
    pub fn with_policy(mut self, policy: AlertEmissionPolicy) -> Self {
        self.emission_policy = policy;
        self
    }

    /// Appends a key-value diagnostic evidence entry.
    #[inline]
    pub fn with_evidence(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.evidence.insert(key.into(), value.into());
        self
    }
}
