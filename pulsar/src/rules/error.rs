//! Domain-specific error types for the Rhai rule execution and compilation subsystem.

use std::path::PathBuf;
use thiserror::Error;

/// Errors occurring during Rhai rule loading, compilation, evaluation, or file watching.
#[derive(Debug, Error)]
pub enum RuleError {
    /// File system input/output failure when reading a rule file.
    #[error("Failed to read rule file '{path}': {source}")]
    Io {
        /// Path to the rule file that encountered the IO failure.
        path: PathBuf,
        /// Underlying IO error.
        #[source]
        source: std::io::Error,
    },

    /// Rhai script syntax error or parse failure.
    #[error("Syntax error in rule '{rule}': {message}")]
    Syntax {
        /// Name or path of the offending rule script.
        rule: String,
        /// Human-readable compiler error description.
        message: String,
    },

    /// Missing, invalid, or malformed metadata in rule script.
    #[error("Metadata error in rule '{rule}': {message}")]
    Metadata {
        /// Name or path of the rule with missing/invalid metadata.
        rule: String,
        /// Description of the metadata validation error.
        message: String,
    },

    /// Specified rules directory does not exist or contains no valid rules.
    #[error("Rules directory '{path}' not found or contains no valid rules")]
    DirectoryEmpty {
        /// Path to the missing or empty rules directory.
        path: PathBuf,
    },

    /// Runtime evaluation error, type mismatch, or fuel exhaustion.
    #[error("Evaluation error in rule '{rule}': {message}")]
    Evaluation {
        /// Name of the rule executing when the failure occurred.
        rule: String,
        /// Detailed runtime error message from the Rhai engine.
        message: String,
    },

    /// File system watcher subscription or event processing error.
    #[error("Rule file watcher failure: {0}")]
    Watcher(#[from] notify::Error),

    /// Synchronization lock poisoned by a panicking thread.
    #[error("Internal rule synchronization lock poisoned: {0}")]
    LockPoisoned(&'static str),
}
