//! Centralized Alert Manager and bounded event distribution coordinator.

use std::collections::VecDeque;
use parking_lot::RwLock;

use crate::alerts::model::AlertRecord;
use crate::alerts::sinks::{AlertSink, ConsoleAlertSink};

/// Centralized manager for buffering, indexing, and dispatching analytical alerts.
///
/// Implements a bounded FIFO ring buffer to prevent unbounded memory growth during alert storms,
/// and fans out alerts to registered [`AlertSink`] subscribers.
pub struct AlertManager {
    /// Bounded ring buffer of recent alerts.
    alerts: RwLock<VecDeque<AlertRecord>>,
    /// Registered analytical output sinks.
    sinks: RwLock<Vec<Box<dyn AlertSink + Send + Sync>>>,
    /// Maximum number of alerts retained in the in-memory ring buffer.
    max_capacity: usize,
}

impl Default for AlertManager {
    fn default() -> Self {
        Self::new(10_000)
    }
}

impl AlertManager {
    /// Creates a new `AlertManager` with the specified ring buffer capacity.
    ///
    /// # Arguments
    ///
    /// * `max_capacity` - Maximum alerts to retain before evicting the oldest record.
    ///
    /// # Returns
    ///
    /// An initialized [`AlertManager`].
    pub fn new(max_capacity: usize) -> Self {
        let default_sink: Box<dyn AlertSink + Send + Sync> = Box::new(ConsoleAlertSink::new());
        Self {
            alerts: RwLock::new(VecDeque::with_capacity(max_capacity.min(1_000))),
            sinks: RwLock::new(vec![default_sink]),
            max_capacity: max_capacity.max(100),
        }
    }

    /// Emits a new detection alert, storing it in the bounded buffer and notifying all sinks.
    ///
    /// # Arguments
    ///
    /// * `alert` - The generated alert record.
    pub fn emit(&self, alert: AlertRecord) {
        // 1. Dispatch to all registered alert sinks
        {
            let sinks = self.sinks.read();
            for sink in sinks.iter() {
                sink.on_alert(&alert);
            }
        }

        // 2. Commit to bounded in-memory ring buffer
        {
            let mut alerts = self.alerts.write();
            if alerts.len() >= self.max_capacity {
                alerts.pop_front();
            }
            alerts.push_back(alert);
        }
    }

    /// Registers an additional alert sink subscriber.
    ///
    /// # Arguments
    ///
    /// * `sink` - The boxed alert sink to add.
    pub fn add_sink(&self, sink: Box<dyn AlertSink + Send + Sync>) {
        self.sinks.write().push(sink);
    }

    /// Returns the N most recent alerts in reverse chronological order (newest first).
    ///
    /// # Arguments
    ///
    /// * `count` - Maximum alerts to retrieve.
    ///
    /// # Returns
    ///
    /// A vector of [`AlertRecord`] clones.
    pub fn recent_alerts(&self, count: usize) -> Vec<AlertRecord> {
        let alerts = self.alerts.read();
        alerts.iter().rev().take(count).cloned().collect()
    }

    /// Returns the total number of alerts currently retained in the ring buffer.
    #[inline]
    pub fn len(&self) -> usize {
        self.alerts.read().len()
    }

    /// Checks whether the alert ring buffer is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.alerts.read().is_empty()
    }

    /// Clears all retained alerts from the ring buffer (primarily useful in tests).
    pub fn clear(&self) {
        self.alerts.write().clear();
    }
}
