//! Rhai engine configuration, sandboxing policies, and AST evaluation.
//!
//! Enforces deterministic runtime constraints on script execution: fuel limits, call depth limits,
//! and isolated memory execution without ambient OS access.

use rhai::{Engine, OptimizationLevel, Scope};

use super::bindings;
use super::error::RuleError;
use super::types::CompiledRule;
use super::verdict::RuleVerdict;

/// Creates and configures a sandboxed `rhai::Engine` instance.
///
/// Imposes strict execution limits to ensure safety and prevent unbounded CPU usage:
/// - Operation fuel limit: 50,000 instructions (guarantees sub-millisecond termination, scalable if needed).
/// - Call depth limit: 10 stack frames (prevents recursive stack overflows).
/// - String size limit: 2,048 characters.
/// - In-memory sandbox: No ambient OS filesystem, network, or process spawning access.
///
/// # Returns
///
/// A sandboxed [`Engine`] ready for rule AST compilation and execution.
pub fn create_sandboxed_engine() -> Engine {
    let mut engine = Engine::new();

    // Impose deterministic fuel and recursion safety limits
    engine.set_max_operations(50_000);
    engine.set_max_call_levels(10);
    engine.set_max_string_size(2048);
    engine.set_optimization_level(OptimizationLevel::Simple);

    // Register strongly-typed structs, getters, and helper functions
    bindings::register_bindings(&mut engine);

    engine
}

/// Evaluates a single compiled rule against the provided interpreter scope.
///
/// Executes the script AST and annotates any generated [`RuleVerdict::Alert`]
/// with the rule's identifier for provenance tracking.
///
/// # Arguments
///
/// * `engine` - The sandboxed Rhai engine instance.
/// * `rule` - The pre-compiled rule AST and metadata.
/// * `scope` - Mutable reference to the populated execution scope.
///
/// # Returns
///
/// The resulting [`RuleVerdict`] outcome.
///
/// # Errors
///
/// Returns [`RuleError::Evaluation`] if execution exceeds fuel limits or encounters script runtime errors.
pub fn evaluate_rule(
    engine: &Engine,
    rule: &CompiledRule,
    scope: &mut Scope,
) -> Result<RuleVerdict, RuleError> {
    let mut verdict: RuleVerdict = engine
        .eval_ast_with_scope(scope, &rule.ast)
        .map_err(|err| RuleError::Evaluation {
            rule: rule.metadata.name.clone(),
            message: err.to_string(),
        })?;

    if let RuleVerdict::Alert { ref mut rule_name, .. } = verdict
        && rule_name.is_none()
    {
        *rule_name = Some(rule.metadata.name.clone());
    }

    Ok(verdict)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::Arc;
    use super::*;
    use crate::rules::types::{EventType, RuleMetadata, RuleStage};

    #[test]
    fn test_sandboxed_infinite_loop_fuel_limit() {
        let engine = create_sandboxed_engine();
        let script = "while true { let x = 1; }";
        let ast = engine.compile(script).expect("compile should succeed");

        let rule = CompiledRule {
            metadata: RuleMetadata {
                name: "infinite_loop_test".to_string(),
                event_type: EventType::ObProcessHandle,
                stage: RuleStage::Detection,
                severity: None,
                mitre_tactic: None,
                mitre_technique: None,
            },
            file_path: PathBuf::from("test.rhai"),
            ast: Arc::new(ast),
        };

        let mut scope = Scope::new();
        let result = evaluate_rule(&engine, &rule, &mut scope);
        assert!(result.is_err(), "Script should terminate on fuel limit");
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("Too many operations"),
            "Error must indicate operation fuel exhaustion: {err}"
        );
    }
}
