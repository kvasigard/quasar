//! Background filesystem watcher providing instant hot-reloading for `.rhai` rules.

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use notify::{Config, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use rhai::Engine;

use super::cache::SuppressionCache;
use super::error::RuleError;
use super::loader::compile_file;
use super::types::RuleIndex;

/// Checks if a filesystem notification event pertains to at least one `.rhai` rule file.
fn is_rhai_event(event: &notify::Event) -> bool {
    matches!(
        event.kind,
        EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_)
    ) && event
        .paths
        .iter()
        .any(|p| p.extension().is_some_and(|ext| ext == "rhai"))
}

/// Spawns a background thread that monitors the rules directory and hot-reloads ASTs upon changes.
///
/// # Arguments
///
/// * `rules_dir` - Path to the directory containing `.rhai` rule files.
/// * `engine` - Shared reference to the Rhai engine.
/// * `rule_index` - Thread-safe storage for active compiled rules.
/// * `cache` - Shared reference to the [`SuppressionCache`] cleared on rule updates.
/// * `shutdown_flag` - Atomic flag signaling thread termination.
///
/// # Returns
///
/// A handle to the background watcher thread, or a [`RuleError`] if watching could not be initialized.
///
/// # Errors
///
/// Returns [`RuleError::Watcher`] if the platform file notification backend fails to initialize.
pub fn spawn_rule_watcher(
    rules_dir: PathBuf,
    engine: Arc<Engine>,
    rule_index: Arc<RwLock<RuleIndex>>,
    cache: Arc<SuppressionCache>,
    shutdown_flag: Arc<AtomicBool>,
) -> Result<JoinHandle<()>, RuleError> {
    let (tx, rx) = std::sync::mpsc::channel();

    let mut watcher = RecommendedWatcher::new(
        move |res| {
            if let Ok(event) = res {
                let _ = tx.send(event);
            }
        },
        Config::default(),
    )?;

    if rules_dir.exists() {
        watcher.watch(&rules_dir, RecursiveMode::Recursive)?;
        log::info!(
            target: "rules",
            "Rule hot-reload watcher active on '{}'",
            rules_dir.display()
        );
    } else {
        log::warn!(
            target: "rules",
            "Directory '{}' does not exist; dynamic file watching inactive.",
            rules_dir.display()
        );
    }

    let handle = thread::Builder::new()
        .name("rule-watcher".to_string())
        .spawn(move || {
            // Keep watcher alive inside this thread scope
            let _watcher = watcher;

            while !shutdown_flag.load(Ordering::Relaxed) {
                // Poll for file modification events with a 500ms timeout
                match rx.recv_timeout(Duration::from_millis(500)) {
                    Ok(event) => {
                        if is_rhai_event(&event) {
                            let mut modified_paths: HashSet<PathBuf> = event
                                .paths
                                .into_iter()
                                .filter(|p| p.extension().is_some_and(|ext| ext == "rhai"))
                                .collect();

                            // Debounce editor writes slightly (150 ms) and accumulate all paths
                            // touched across the debounce window so multi-file saves are never lost.
                            thread::sleep(Duration::from_millis(150));
                            while let Ok(subsequent) = rx.try_recv() {
                                if is_rhai_event(&subsequent) {
                                    for path in subsequent.paths {
                                        if path.extension().is_some_and(|ext| ext == "rhai") {
                                            modified_paths.insert(path);
                                        }
                                    }
                                }
                            }

                            log::debug!(
                                target: "rules",
                                "Processing {} debounced rule file path(s)",
                                modified_paths.len()
                            );

                            let mut index_changed = false;
                            for path in &modified_paths {
                                if !path.exists() {
                                    let mut guard = rule_index
                                        .write()
                                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                                    if guard.remove_by_path(path) {
                                        index_changed = true;
                                        log::info!(
                                            target: "rules",
                                            "Unloaded rule from '{}'",
                                            path.display()
                                        );
                                    }
                                    continue;
                                }

                                match compile_file(&engine, path) {
                                    Ok(compiled) => {
                                        let name = compiled.metadata.name.clone();
                                        let stage = compiled.metadata.stage;
                                        let event_type = compiled.metadata.event_type;
                                        {
                                            let mut guard = rule_index
                                                .write()
                                                .unwrap_or_else(|poisoned| poisoned.into_inner());
                                            guard.upsert(compiled);
                                        }
                                        index_changed = true;
                                        log::info!(
                                            target: "rules",
                                            "Hot-reloaded {:?} rule '{}' ({:?}) from '{}'",
                                            stage,
                                            name,
                                            event_type,
                                            path.display()
                                        );
                                    }
                                    Err(err) => {
                                        log::error!(
                                            target: "rules",
                                            "Failed to compile modified rule '{}': {}",
                                            path.display(),
                                            err
                                        );
                                    }
                                }
                            }

                            if index_changed {
                                cache.clear();
                            }
                        }
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                        // Regular timeout tick, check shutdown_flag
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                        break;
                    }
                }
            }

            log::debug!(target: "rules", "Rule hot-reload watcher thread shutting down.");
        })
        .expect("Failed to spawn rule-watcher thread");

    Ok(handle)
}
