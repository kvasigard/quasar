//! Decoupled Alert and Detection Management Subsystem.
//!
//! Exposes the centralized [`AlertManager`] singleton, structured [`AlertRecord`] definitions,
//! and [`AlertSink`] subscribers for routing detections out of analytical sinks.

pub mod manager;
pub mod model;
pub mod sinks;

#[cfg(test)]
mod tests;

use std::sync::LazyLock;

pub use manager::AlertManager;
pub use model::{AlertEmissionPolicy, AlertId, AlertRecord, AlertSeverity};
pub use sinks::{AlertSink, ConsoleAlertSink, TelemetryForwarderSink};

/// Global `AlertManager` singleton instance.
pub static ALERT_MANAGER: LazyLock<AlertManager> = LazyLock::new(AlertManager::default);

/// Returns a reference to the global `AlertManager` singleton.
///
/// # Returns
///
/// A static reference to the shared [`AlertManager`].
#[inline]
pub fn alert_manager() -> &'static AlertManager {
    &ALERT_MANAGER
}
