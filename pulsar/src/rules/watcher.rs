//! Background filesystem watcher providing instant hot-reloading for `.rhai` rules.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use notify::{Config, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use rhai::Engine;

use super::error::RuleError;
use super::loader::compile_file;
use super::types::RuleIndex;

/// Spawns a background thread that monitors the rules directory and hot-reloads ASTs upon changes.
///
/// # Arguments
///
/// * `rules_dir` - Path to the directory containing `.rhai` rule files.
/// * `engine` - Shared reference to the Rhai engine.
/// * `rule_index` - Thread-safe storage for active compiled rules.
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
                        let is_relevant = match event.kind {
                            EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_) => {
                                event.paths.iter().any(|p| {
                                    p.extension().is_some_and(|ext| ext == "rhai")
                                })
                            }
                            _ => false,
                        };

                        if is_relevant {
                            // Debounce editor writes slightly (150 ms)
                            thread::sleep(Duration::from_millis(150));
                            // Drain queued rapid events from the channel
                            while rx.try_recv().is_ok() {}

                            log::debug!(
                                target: "rules",
                                "Processing filesystem notification event: {:?}",
                                event.kind
                            );

                            for path in &event.paths {
                                if path.extension().is_none_or(|ext| ext != "rhai") {
                                    continue;
                                }

                                if !path.exists() {
                                    let mut guard = rule_index
                                        .write()
                                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                                    if guard.remove_by_path(path) {
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
