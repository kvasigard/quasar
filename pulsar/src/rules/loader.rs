//! Script discovery, compilation, and declarative metadata parsing.
//!
//! Scans configured directories for `.rhai` files, parses script syntax into
//! pre-compiled ASTs, calls `fn rule_info()` to extract declarative metadata,
//! and populates a multi-dimensional [`RuleIndex`].

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rhai::{Engine, Scope};

use super::error::RuleError;
use super::types::{CompiledRule, EventType, RuleIndex, RuleMetadata, RuleStage};
use crate::alerts::AlertSeverity;

/// Compiles a single rule script from disk and extracts its declarative metadata.
///
/// Validates script syntax, parses the AST, and invokes the script's `fn rule_info()`
/// function to extract name, event subscription, execution stage, and MITRE tags.
///
/// # Arguments
///
/// * `engine` - Reference to the sandboxed Rhai engine instance.
/// * `path` - Filesystem path to the `.rhai` source file.
///
/// # Returns
///
/// A fully compiled [`CompiledRule`] ready for execution and indexing.
///
/// # Errors
///
/// Returns [`RuleError::Io`] if file reading fails, [`RuleError::Syntax`] if the script
/// fails compilation, or [`RuleError::Metadata`] if `rule_info()` is missing or invalid.
pub fn compile_file(engine: &Engine, path: &Path) -> Result<CompiledRule, RuleError> {
    let script = fs::read_to_string(path).map_err(|source| RuleError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let ast = engine.compile(&script).map_err(|err| RuleError::Syntax {
        rule: path.to_string_lossy().to_string(),
        message: err.to_string(),
    })?;

    let mut info_ast = ast.clone();
    info_ast.clear_statements();

    let mut scope = Scope::new();
    let info_map: rhai::Map = engine
        .call_fn(&mut scope, &info_ast, "rule_info", ())
        .map_err(|err| RuleError::Metadata {
            rule: path.to_string_lossy().to_string(),
            message: format!("Failed to call 'fn rule_info()': {err}"),
        })?;

    let name = info_map
        .get("name")
        .and_then(|v| v.clone().into_string().ok())
        .unwrap_or_else(|| {
            path.file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("unnamed_rule")
                .to_string()
        });

    let event_str = info_map
        .get("event")
        .and_then(|v| v.clone().into_string().ok())
        .ok_or_else(|| RuleError::Metadata {
            rule: path.to_string_lossy().to_string(),
            message: "Missing required 'event' string in rule_info()".to_string(),
        })?;

    let event_type = match event_str.as_str() {
        "ObProcessHandle" => EventType::ObProcessHandle,
        other => {
            return Err(RuleError::Metadata {
                rule: path.to_string_lossy().to_string(),
                message: format!("Unknown event type '{other}' in rule_info()"),
            });
        }
    };

    let stage_str = info_map
        .get("stage")
        .and_then(|v| v.clone().into_string().ok())
        .ok_or_else(|| RuleError::Metadata {
            rule: path.to_string_lossy().to_string(),
            message: "Missing required 'stage' string in rule_info()".to_string(),
        })?;

    let stage = match stage_str.to_lowercase().as_str() {
        "suppression" => RuleStage::Suppression,
        "detection" => RuleStage::Detection,
        other => {
            return Err(RuleError::Metadata {
                rule: path.to_string_lossy().to_string(),
                message: format!(
                    "Invalid stage '{other}' in rule_info(); expected 'suppression' or 'detection'"
                ),
            });
        }
    };

    let severity = info_map
        .get("severity")
        .and_then(|v| v.clone().into_string().ok())
        .map(|s| match s.to_lowercase().as_str() {
            "critical" => AlertSeverity::Critical,
            "high" => AlertSeverity::High,
            "medium" => AlertSeverity::Medium,
            "low" => AlertSeverity::Low,
            _ => AlertSeverity::Informational,
        });

    let mitre_tactic = info_map
        .get("mitre_tactic")
        .and_then(|v| v.clone().into_string().ok());

    let mitre_technique = info_map
        .get("mitre_technique")
        .and_then(|v| v.clone().into_string().ok());

    let metadata = RuleMetadata {
        name,
        event_type,
        stage,
        severity,
        mitre_tactic,
        mitre_technique,
    };

    Ok(CompiledRule {
        metadata,
        file_path: path.to_path_buf(),
        ast: Arc::new(ast),
    })
}

/// Loads and compiles all `.rhai` rules discovered within the specified directory.
///
/// # Arguments
///
/// * `engine` - Reference to the sandboxed Rhai engine instance.
/// * `dir` - Root filesystem path containing `.rhai` rule files.
///
/// # Returns
///
/// A populated [`RuleIndex`] containing all successfully compiled rules.
///
/// # Errors
///
/// Returns [`RuleError::DirectoryEmpty`] if the directory does not exist or contains no valid rules.
pub fn load_rules_from_dir(engine: &Engine, dir: &Path) -> Result<RuleIndex, RuleError> {
    if !dir.exists() {
        return Err(RuleError::DirectoryEmpty {
            path: dir.to_path_buf(),
        });
    }

    let mut files = Vec::new();
    collect_rhai_files(dir, &mut files);

    let mut rule_index = RuleIndex::new();

    for path in files {
        match compile_file(engine, &path) {
            Ok(rule) => {
                log::debug!(
                    target: "rules",
                    "Compiled {:?} rule '{}' ({:?}) from {}",
                    rule.metadata.stage,
                    rule.metadata.name,
                    rule.metadata.event_type,
                    path.display()
                );
                rule_index.insert(rule);
            }
            Err(err) => {
                log::error!(
                    target: "rules",
                    "Failed to compile rule file '{}': {}",
                    path.display(),
                    err
                );
            }
        }
    }

    if rule_index.total_count() == 0 {
        return Err(RuleError::DirectoryEmpty {
            path: dir.to_path_buf(),
        });
    }

    Ok(rule_index)
}

fn collect_rhai_files(dir: &Path, out: &mut Vec<PathBuf>) {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.filter_map(|e| e.ok()) {
            let path = entry.path();
            if path.is_dir() {
                collect_rhai_files(&path, out);
            } else if path.is_file() && path.extension().is_some_and(|ext| ext == "rhai") {
                out.push(path);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::engine::create_sandboxed_engine;

    #[test]
    fn test_compile_file_with_metadata() {
        let engine = create_sandboxed_engine();
        let script = r#"
            fn rule_info() {
                #{
                    name: "test_rule",
                    event: "ObProcessHandle",
                    stage: "detection",
                    severity: "high",
                    mitre_tactic: "Credential Access",
                    mitre_technique: "T1003.001",
                }
            }
            return pass();
        "#;

        let temp_dir = std::env::temp_dir();
        let test_file = temp_dir.join("quasar_test_rule.rhai");
        fs::write(&test_file, script).unwrap();

        let compiled = compile_file(&engine, &test_file).unwrap();
        assert_eq!(compiled.metadata.name, "test_rule");
        assert_eq!(compiled.metadata.event_type, EventType::ObProcessHandle);
        assert_eq!(compiled.metadata.stage, RuleStage::Detection);
        assert_eq!(compiled.metadata.severity, Some(AlertSeverity::High));

        let _ = fs::remove_file(test_file);
    }

    #[test]
    fn test_missing_metadata_error() {
        let engine = create_sandboxed_engine();
        let script = "return pass();";

        let temp_dir = std::env::temp_dir();
        let test_file = temp_dir.join("quasar_invalid_rule.rhai");
        fs::write(&test_file, script).unwrap();

        let result = compile_file(&engine, &test_file);
        assert!(matches!(result, Err(RuleError::Metadata { .. })));

        let _ = fs::remove_file(test_file);
    }

    #[test]
    fn test_load_disk_rules() {
        let engine = create_sandboxed_engine();
        let candidates = [Path::new("../rules"), Path::new("rules")];
        for dir in &candidates {
            if dir.exists() {
                let rule_index = load_rules_from_dir(&engine, dir).expect("Rules directory should load");
                assert!(rule_index.total_count() >= 3, "Must find at least 3 disk rules");
                assert_eq!(rule_index.get(EventType::ObProcessHandle, RuleStage::Suppression).len(), 1);
                assert_eq!(rule_index.get(EventType::ObProcessHandle, RuleStage::Detection).len(), 2);
                return;
            }
        }
    }
}
