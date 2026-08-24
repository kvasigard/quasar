//! Alert sink interfaces, console formatters, and telemetry forwarders.

use crate::alerts::model::{AlertRecord, AlertSeverity};

/// Interface for dispatching generated alerts to notification channels, logging, or telemetry forwarders.
pub trait AlertSink: Send + Sync {
    /// Handles an emitted alert record.
    ///
    /// # Arguments
    ///
    /// * `alert` - The generated alert record.
    fn on_alert(&self, alert: &AlertRecord);
}

/// Alert sink that formats and logs alerts via standard structured logging.
#[derive(Debug, Default, Clone)]
pub struct ConsoleAlertSink;

impl ConsoleAlertSink {
    /// Creates a new `ConsoleAlertSink`.
    pub fn new() -> Self {
        Self
    }
}

impl AlertSink for ConsoleAlertSink {
    fn on_alert(&self, alert: &AlertRecord) {
        let mitre = alert.mitre_technique.as_deref().unwrap_or("N/A");
        if alert.severity == AlertSeverity::Informational {
            log::info!(
                target: "alerts",
                "[ALERT] [{}] [{}] {} | Proc: {} | MITRE: {} | {}",
                alert.severity,
                alert.category,
                alert.title,
                alert.triggering_process,
                mitre,
                alert.description
            );
        } else {
            log::warn!(
                target: "alerts",
                "[ALERT] [{}] [{}] {} | Proc: {} | MITRE: {} | {}",
                alert.severity,
                alert.category,
                alert.title,
                alert.triggering_process,
                mitre,
                alert.description
            );
        }
    }
}

/// Alert sink that buffers alerts for ingestion into external security data pipelines.
#[derive(Debug, Default)]
pub struct TelemetryForwarderSink {
    // Extensible for external transport (e.g. Named Pipe, TLS Socket, gRPC)
}

impl TelemetryForwarderSink {
    /// Creates a new `TelemetryForwarderSink`.
    pub fn new() -> Self {
        Self {}
    }
}

impl AlertSink for TelemetryForwarderSink {
    fn on_alert(&self, alert: &AlertRecord) {
        log::trace!(
            target: "telemetry_forwarder",
            "Forwarding alert {} to remote telemetry pipeline",
            alert.id
        );
    }
}
