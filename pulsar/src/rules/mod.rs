//! Embedded Rhai Scripting Rule Engine Subsystem.
//!
//! Provides dynamic, sandboxed evaluation of security rules for false-positive
//! suppression and behavioral threat classification with sub-millisecond hot-reloading.

pub mod bindings;
pub mod cache;
pub mod engine;
pub mod error;
pub mod loader;
pub mod types;
pub mod verdict;
pub mod watcher;

use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, RwLock};
use std::thread::JoinHandle;

use rhai::{Engine, Scope};

pub use cache::SuppressionCache;
pub use error::RuleError;
pub use types::{CompiledRule, EventType, RuleIndex, RuleMetadata, RuleStage, ScriptableEvent};
pub use verdict::RuleVerdict;

/// Primary facade for evaluating telemetry events against compiled Rhai rules.
#[derive(Debug, Clone)]
pub struct RuleEngine {
    engine: Arc<Engine>,
    rules: Arc<RwLock<RuleIndex>>,
    cache: Arc<SuppressionCache>,
}

impl RuleEngine {
    /// Initializes the `RuleEngine` by scanning and compiling rules from the specified directory.
    ///
    /// # Arguments
    ///
    /// * `rules_dir` - Filesystem path containing `.rhai` rule files.
    ///
    /// # Returns
    ///
    /// An initialized [`RuleEngine`] instance.
    ///
    /// # Errors
    ///
    /// Returns [`RuleError::DirectoryEmpty`] if the directory does not exist or contains no valid rules.
    pub fn load(rules_dir: impl AsRef<Path>) -> Result<Self, RuleError> {
        let engine = Arc::new(engine::create_sandboxed_engine());
        let rules = loader::load_rules_from_dir(&engine, rules_dir.as_ref())?;

        Ok(Self {
            engine,
            rules: Arc::new(RwLock::new(rules)),
            cache: Arc::new(SuppressionCache::new()),
        })
    }

    /// Initializes an empty `RuleEngine` containing no active rules.
    ///
    /// Useful for testing or when telemetry evaluation operates solely on baseline heuristics.
    ///
    /// # Returns
    ///
    /// An initialized [`RuleEngine`] populated with an empty [`RuleIndex`].
    pub fn empty() -> Self {
        let engine = Arc::new(engine::create_sandboxed_engine());
        Self {
            engine,
            rules: Arc::new(RwLock::new(RuleIndex::new())),
            cache: Arc::new(SuppressionCache::new()),
        }
    }

    /// Constructs a `RuleEngine` populated with an explicit pre-compiled index.
    ///
    /// # Arguments
    ///
    /// * `rules` - Pre-compiled rule index.
    #[cfg(test)]
    pub fn from_index(rules: RuleIndex) -> Self {
        let engine = Arc::new(engine::create_sandboxed_engine());
        Self {
            engine,
            rules: Arc::new(RwLock::new(rules)),
            cache: Arc::new(SuppressionCache::new()),
        }
    }

    /// Evaluates an enriched telemetry event against the compiled rule index and suppression cache.
    ///
    /// # Arguments
    ///
    /// * `event` - Reference to any enriched telemetry event implementing [`ScriptableEvent`].
    ///
    /// # Returns
    ///
    /// The resulting [`RuleVerdict`].
    pub fn evaluate<E: ScriptableEvent>(&self, event: &E) -> RuleVerdict {
        let event_type = event.event_type();

        // Fast-path: short-circuit evaluation if this caller and operation are already cached as suppressed
        if let Some((pid, access)) = event.suppression_key()
            && self.cache.is_suppressed(event_type, pid, access)
        {
            return RuleVerdict::Suppress {
                reason: "Active in-memory suppression cache hit".to_string(),
                cooldown_seconds: 0,
            };
        }

        let index_guard = self
            .rules
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        let mut scope = Scope::new();
        event.populate_scope(&mut scope);
        let base_len = scope.len();

        // Whitelist phase: false-positive filters run before detection heuristics
        for rule in index_guard.get(event_type, RuleStage::Suppression) {
            scope.rewind(base_len);

            match engine::evaluate_rule(&self.engine, rule, &mut scope) {
                Ok(RuleVerdict::Suppress {
                    reason,
                    cooldown_seconds,
                }) => {
                    // Record suppression cooldown so subsequent events from this PID skip Rhai
                    if let Some((pid, access)) = event.suppression_key() {
                        self.cache.insert(event_type, pid, access, cooldown_seconds);
                    }
                    return RuleVerdict::Suppress {
                        reason,
                        cooldown_seconds,
                    };
                }
                Ok(RuleVerdict::Alert { .. }) => {
                    // A suppression rule returned an Alert. Suppressors are strictly whitelists;
                    // alerting here indicates a rule authoring error. We log a warning so the author
                    // can fix the rule, and continue evaluating other suppressors without alerting.
                    log::warn!(
                        target: "rules",
                        "Suppressor rule '{}' returned an Alert verdict instead of Pass/Suppress; ignoring alert.",
                        rule.metadata.name
                    );
                }
                Ok(RuleVerdict::Pass) => continue,
                Err(err) => {
                    log::error!(
                        target: "rules",
                        "Error evaluating suppressor '{}': {}",
                        rule.metadata.name,
                        err
                    );
                }
            }
        }

        // Detection phase: behavioral heuristics only evaluate against telemetry that passed all whitelists
        for rule in index_guard.get(event_type, RuleStage::Detection) {
            scope.rewind(base_len);

            match engine::evaluate_rule(&self.engine, rule, &mut scope) {
                Ok(verdict @ RuleVerdict::Alert { .. }) => {
                    // First alert wins: stops further rule evaluation to provide deterministic attribution
                    return verdict;
                }
                Ok(RuleVerdict::Suppress { .. }) => {
                    // A detection rule returned Suppress. Detection rules cannot unilaterally whitelist
                    // activity. Whitelists must be registered in Stage::Suppression to ensure they run
                    // before any detector. We log a warning to notify of the misconfiguration.
                    log::warn!(
                        target: "rules",
                        "Detector rule '{}' returned a Suppress verdict; ignoring.",
                        rule.metadata.name
                    );
                }
                Ok(RuleVerdict::Pass) => continue,
                Err(err) => {
                    log::error!(
                        target: "rules",
                        "Error evaluating detector '{}': {}",
                        rule.metadata.name,
                        err
                    );
                }
            }
        }

        RuleVerdict::Pass
    }

    /// Prunes suppression entries when a process terminates, preventing PID-recycling collisions.
    ///
    /// # Arguments
    ///
    /// * `pid` - OS process identifier of the terminated process.
    pub fn prune_process(&self, pid: u32) {
        self.cache.prune_process(pid);
    }

    /// Spawns a background file watcher thread for dynamic hot-reloading of rules on disk.
    ///
    /// # Arguments
    ///
    /// * `rules_dir` - Filesystem path to monitor for `.rhai` modifications.
    /// * `shutdown_flag` - Atomic flag signaling thread termination on agent shutdown.
    ///
    /// # Returns
    ///
    /// A [`JoinHandle`] to the background worker thread.
    ///
    /// # Errors
    ///
    /// Returns [`RuleError::Watcher`] if file notification subscription fails.
    pub fn spawn_watcher(
        &self,
        rules_dir: PathBuf,
        shutdown_flag: Arc<AtomicBool>,
    ) -> Result<JoinHandle<()>, RuleError> {
        watcher::spawn_rule_watcher(
            rules_dir,
            Arc::clone(&self.engine),
            Arc::clone(&self.rules),
            Arc::clone(&self.cache),
            shutdown_flag,
        )
    }

    /// Returns the current count of loaded rules.
    ///
    /// # Returns
    ///
    /// Total number of active suppressor and detector rules in memory.
    pub fn rule_count(&self) -> usize {
        self.rules
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .total_count()
    }

    /// Returns a reference to the internal suppression cache.
    ///
    /// # Returns
    ///
    /// Reference to the thread-safe [`SuppressionCache`].
    pub fn cache(&self) -> &SuppressionCache {
        &self.cache
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alerts::AlertSeverity;
    use crate::enrichment::lsass::enrich_lsass_access;
    use shared::ring_buffer::LsassAccessEvent;
    use std::fs;

    fn compile_test_rule(script: &str) -> CompiledRule {
        let engine = engine::create_sandboxed_engine();
        let temp_dir = std::env::temp_dir();
        let file = temp_dir.join(format!("test_rule_{}.rhai", uuid::Uuid::new_v4()));
        fs::write(&file, script).unwrap();
        let rule = loader::compile_file(&engine, &file).unwrap();
        let _ = fs::remove_file(file);
        rule
    }

    fn create_mock_event(
        source_pid: u32,
        target_pid: u32,
        desired: u32,
        granted: u32,
        sig: u8,
        name: &str,
    ) -> LsassAccessEvent {
        LsassAccessEvent::new(
            source_pid,
            target_pid,
            desired,
            granted,
            0x3000,
            sig,
            0,
            1,
            name.as_bytes(),
        )
    }

    #[test]
    fn test_taskmgr_rule_evaluation_and_caching() {
        let taskmgr_script = r#"
            fn rule_info() {
                #{
                    name: "taskmgr_suppressor",
                    event: "ObProcessHandle",
                    stage: "suppression",
                }
            }
            if event.short_name == "Taskmgr.exe" && event.desired_access == 0x1410 {
                return suppress("Task Manager diagnostic polling", 0);
            }
            return pass();
        "#;

        let rule = compile_test_rule(taskmgr_script);
        let mut index = RuleIndex::new();
        index.insert(rule);

        let engine = RuleEngine::from_index(index);

        let raw_event = create_mock_event(8800, 816, 0x1410, 0x1410, 14, "Taskmgr.exe");
        let enriched = enrich_lsass_access(&raw_event);

        // First evaluation: evaluated by Rhai suppressor and cached
        let verdict = engine.evaluate(&enriched);
        assert!(
            matches!(verdict, RuleVerdict::Suppress { .. }),
            "Expected Suppress verdict"
        );

        // Second evaluation: served from fast cache hit (< 5 ns)
        let second_verdict = engine.evaluate(&enriched);
        assert!(matches!(second_verdict, RuleVerdict::Suppress { .. }));
        if let RuleVerdict::Suppress { reason, .. } = second_verdict {
            assert!(reason.contains("cache hit"));
        }

        // Process termination prunes cache
        engine.prune_process(8800);
        assert!(
            !engine
                .cache
                .is_suppressed(EventType::ObProcessHandle, 8800, 0x1410)
        );
    }

    #[test]
    fn test_comsvcs_dump_detection() {
        let comsvcs_script = r#"
            fn rule_info() {
                #{
                    name: "comsvcs_detection",
                    event: "ObProcessHandle",
                    stage: "detection",
                    severity: "critical",
                    mitre_tactic: "Credential Access",
                    mitre_technique: "T1003.001",
                }
            }
            if contains_ic(actor.command_line, "comsvcs") && contains_ic(actor.command_line, "minidump") {
                return alert(
                    "LSASS Memory Access via Comsvcs DLL",
                    "Process attempted minidump export"
                );
            }
            return pass();
        "#;

        let rule = compile_test_rule(comsvcs_script);
        let mut index = RuleIndex::new();
        index.insert(rule);

        let engine = RuleEngine::from_index(index);

        let raw_event = create_mock_event(5120, 816, 0x001FFFFF, 0x1000, 14, "rundll32.exe");
        let mut enriched = enrich_lsass_access(&raw_event);
        enriched.actor.command_line =
            "rundll32.exe comsvcs.dll, MiniDump 816 C:\\temp\\lsass.dmp full".to_string();

        let verdict = engine.evaluate(&enriched);
        match verdict {
            RuleVerdict::Alert {
                severity,
                title,
                mitre_tactic,
                mitre_technique,
                ..
            } => {
                assert_eq!(severity, AlertSeverity::Critical);
                assert!(title.contains("Comsvcs DLL"));
                assert_eq!(mitre_tactic, "Credential Access");
                assert_eq!(mitre_technique, "T1003.001");
            }
            other => panic!("Expected Alert verdict, got: {:?}", other),
        }
    }

    #[test]
    fn test_untrusted_read_detection() {
        let untrusted_script = r#"
            fn rule_info() {
                #{
                    name: "untrusted_read_detection",
                    event: "ObProcessHandle",
                    stage: "detection",
                    severity: "high",
                    mitre_tactic: "Credential Access",
                    mitre_technique: "T1003.001",
                }
            }
            if event.signature_level < 8 && has_mask(event.desired_access, 0x0010) {
                return alert(
                    "LSASS Memory Access by Untrusted Process",
                    "Unsigned process requested PROCESS_VM_READ access"
                );
            }
            return pass();
        "#;

        let rule = compile_test_rule(untrusted_script);
        let mut index = RuleIndex::new();
        index.insert(rule);

        let engine = RuleEngine::from_index(index);

        let raw_event = create_mock_event(7777, 816, 0x1010, 0x1000, 0, "mimikatz.exe");
        let enriched = enrich_lsass_access(&raw_event);

        let verdict = engine.evaluate(&enriched);
        match verdict {
            RuleVerdict::Alert {
                severity,
                title,
                mitre_technique,
                ..
            } => {
                assert_eq!(severity, AlertSeverity::High);
                assert!(title.contains("Untrusted Process"));
                assert_eq!(mitre_technique, "T1003.001");
            }
            other => panic!("Expected Alert verdict, got: {:?}", other),
        }
    }

    #[test]
    fn test_benign_pollers_anti_bypass_and_suppression() {
        let engine = engine::create_sandboxed_engine();
        let candidates = [
            Path::new("../rules/suppressors/lsass/benign_pollers.rhai"),
            Path::new("rules/suppressors/lsass/benign_pollers.rhai"),
        ];

        let rule_path = candidates
            .iter()
            .find(|p| p.exists())
            .expect("benign_pollers.rhai must exist");
        let rule =
            loader::compile_file(&engine, rule_path).expect("Must compile benign_pollers.rhai");

        let mut index = RuleIndex::new();
        index.insert(rule);
        let rule_engine = RuleEngine::from_index(index);

        // 1. Authentic Windows Task Manager (System32 path, access 0x1410, high integrity, signed >= 8)
        let raw_taskmgr = create_mock_event(8801, 816, 0x1410, 0x1000, 14, "Taskmgr.exe");
        let mut enriched_taskmgr = enrich_lsass_access(&raw_taskmgr);
        enriched_taskmgr.raw.integrity_level = 0x3000;
        enriched_taskmgr.actor.name = "Taskmgr.exe".to_string();
        enriched_taskmgr.actor.image_path = "C:\\Windows\\System32\\Taskmgr.exe".to_string();
        enriched_taskmgr.actor.integrity_level = 0x3000;
        let verdict = rule_engine.evaluate(&enriched_taskmgr);
        assert!(
            matches!(verdict, RuleVerdict::Suppress { .. }),
            "Authentic Taskmgr must be suppressed"
        );

        // 2. Bypass attempt: Fake Taskmgr running from Desktop (path spoofing)
        let raw_fake = create_mock_event(8802, 816, 0x1410, 0x1000, 14, "Taskmgr.exe");
        let mut fake_taskmgr = enrich_lsass_access(&raw_fake);
        fake_taskmgr.raw.integrity_level = 0x3000;
        fake_taskmgr.actor.name = "Taskmgr.exe".to_string();
        fake_taskmgr.actor.image_path = "C:\\Users\\Attacker\\Desktop\\Taskmgr.exe".to_string();
        fake_taskmgr.actor.integrity_level = 0x3000;
        let fake_verdict = rule_engine.evaluate(&fake_taskmgr);
        assert!(
            matches!(fake_verdict, RuleVerdict::Pass),
            "Fake Taskmgr outside System32 must NOT be suppressed"
        );

        // 3. Bypass attempt: Fake Taskmgr running at low/untrusted integrity (< 0x2000)
        let raw_low = create_mock_event(8803, 816, 0x1410, 0x1000, 14, "Taskmgr.exe");
        let mut low_taskmgr = enrich_lsass_access(&raw_low);
        low_taskmgr.raw.integrity_level = 0x1000;
        low_taskmgr.actor.name = "Taskmgr.exe".to_string();
        low_taskmgr.actor.image_path = "C:\\Windows\\System32\\Taskmgr.exe".to_string();
        low_taskmgr.actor.integrity_level = 0x1000;
        let low_verdict = rule_engine.evaluate(&low_taskmgr);
        assert!(
            matches!(low_verdict, RuleVerdict::Pass),
            "Low integrity Taskmgr must NOT be suppressed"
        );

        // 4. Bypass attempt: Taskmgr carrying memory dumping arguments
        let raw_dump = create_mock_event(8804, 816, 0x1410, 0x1000, 14, "Taskmgr.exe");
        let mut dump_taskmgr = enrich_lsass_access(&raw_dump);
        dump_taskmgr.raw.integrity_level = 0x3000;
        dump_taskmgr.actor.name = "Taskmgr.exe".to_string();
        dump_taskmgr.actor.image_path = "C:\\Windows\\System32\\Taskmgr.exe".to_string();
        dump_taskmgr.actor.integrity_level = 0x3000;
        dump_taskmgr.actor.command_line = "Taskmgr.exe /dump lsass".to_string();
        let dump_verdict = rule_engine.evaluate(&dump_taskmgr);
        assert!(
            matches!(dump_verdict, RuleVerdict::Pass),
            "Taskmgr with dump args must NOT be suppressed"
        );

        // 5. Bypass attempt: Taskmgr requesting dumping rights (0x001FFFFF instead of 0x1410)
        let raw_rights = create_mock_event(8805, 816, 0x001FFFFF, 0x1000, 14, "Taskmgr.exe");
        let mut rights_taskmgr = enrich_lsass_access(&raw_rights);
        rights_taskmgr.raw.integrity_level = 0x3000;
        rights_taskmgr.actor.name = "Taskmgr.exe".to_string();
        rights_taskmgr.actor.image_path = "C:\\Windows\\System32\\Taskmgr.exe".to_string();
        rights_taskmgr.actor.integrity_level = 0x3000;
        let rights_verdict = rule_engine.evaluate(&rights_taskmgr);
        assert!(
            matches!(rights_verdict, RuleVerdict::Pass),
            "Taskmgr requesting non-0x1410 rights must NOT be suppressed"
        );

        // 5b. Bypass attempt: Unsigned Taskmgr (signature_level < 8)
        let raw_unsigned = create_mock_event(8806, 816, 0x1410, 0x1000, 0, "Taskmgr.exe");
        let mut unsigned_taskmgr = enrich_lsass_access(&raw_unsigned);
        unsigned_taskmgr.raw.integrity_level = 0x3000;
        unsigned_taskmgr.raw.signature_level = 0;
        unsigned_taskmgr.actor.name = "Taskmgr.exe".to_string();
        unsigned_taskmgr.actor.image_path = "C:\\Windows\\System32\\Taskmgr.exe".to_string();
        unsigned_taskmgr.actor.integrity_level = 0x3000;
        unsigned_taskmgr.actor.signature_level = 0;
        let unsigned_verdict = rule_engine.evaluate(&unsigned_taskmgr);
        assert!(
            matches!(unsigned_verdict, RuleVerdict::Pass),
            "Unsigned Taskmgr must NOT be suppressed"
        );

        // 6. Authentic WMI Provider Host
        let raw_wmi = create_mock_event(4524, 816, 0x1410, 0x1000, 14, "WmiPrvSE.exe");
        let mut enriched_wmi = enrich_lsass_access(&raw_wmi);
        enriched_wmi.raw.integrity_level = 0x4000;
        enriched_wmi.actor.name = "WmiPrvSE.exe".to_string();
        enriched_wmi.actor.image_path = "C:\\Windows\\System32\\wbem\\WmiPrvSE.exe".to_string();
        enriched_wmi.actor.integrity_level = 0x4000;
        let wmi_verdict = rule_engine.evaluate(&enriched_wmi);
        assert!(
            matches!(wmi_verdict, RuleVerdict::Suppress { .. }),
            "Authentic WmiPrvSE must be suppressed"
        );

        // 7. Authentic VMware Tools Guest Agent
        let raw_vmtools = create_mock_event(3340, 816, 0x1410, 0x1000, 8, "vmtoolsd.exe");
        let mut enriched_vmtools = enrich_lsass_access(&raw_vmtools);
        enriched_vmtools.raw.integrity_level = 0x4000;
        enriched_vmtools.actor.name = "vmtoolsd.exe".to_string();
        enriched_vmtools.actor.image_path =
            "C:\\Program Files\\VMware\\VMware Tools\\vmtoolsd.exe".to_string();
        enriched_vmtools.actor.integrity_level = 0x4000;
        let vmtools_verdict = rule_engine.evaluate(&enriched_vmtools);
        assert!(
            matches!(vmtools_verdict, RuleVerdict::Suppress { .. }),
            "Authentic vmtoolsd must be suppressed"
        );
    }
}
