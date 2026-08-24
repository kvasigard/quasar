//! Concurrent, indexed interaction registry and cross-entity activity ledger.

use std::collections::VecDeque;
use std::sync::Arc;
use dashmap::DashMap;
use parking_lot::RwLock;

use crate::context::identity::{EntityId, InteractionId, ProcessKey};
use crate::context::models::interaction::InteractionRecord;

/// Concurrent registry storing and indexing all cross-entity interaction events.
pub struct InteractionRegistry {
    /// Bounded FIFO ring buffer of interaction records.
    records: RwLock<VecDeque<Arc<InteractionRecord>>>,
    /// Fast index by InteractionId.
    by_id: DashMap<InteractionId, Arc<InteractionRecord>>,
    /// Fast index mapping target EntityId to its incoming InteractionIds.
    target_index: DashMap<EntityId, Vec<InteractionId>>,
    /// Fast index mapping source EntityId to its outgoing InteractionIds.
    source_index: DashMap<EntityId, Vec<InteractionId>>,
    /// Maximum capacity of interaction records to retain in memory.
    max_capacity: usize,
}

impl InteractionRegistry {
    /// Creates a new `InteractionRegistry` with the specified maximum capacity.
    ///
    /// # Arguments
    ///
    /// * `max_capacity` - Maximum records to hold in the bounded ring buffer before evicting oldest.
    ///
    /// # Returns
    ///
    /// An empty [`InteractionRegistry`].
    pub fn new(max_capacity: usize) -> Self {
        Self {
            records: RwLock::new(VecDeque::with_capacity(max_capacity.min(10_000))),
            by_id: DashMap::new(),
            target_index: DashMap::new(),
            source_index: DashMap::new(),
            max_capacity,
        }
    }

    /// Records an interaction event into the ledger and updates secondary indices.
    ///
    /// # Arguments
    ///
    /// * `record` - The interaction record to persist and index.
    ///
    /// # Returns
    ///
    /// A shared [`Arc<InteractionRecord>`] reference.
    pub fn record(&self, record: InteractionRecord) -> Arc<InteractionRecord> {
        let id = record.id;
        let source = record.source;
        let target = record.target;
        let record_arc = Arc::new(record);

        // Insert into secondary indices
        self.by_id.insert(id, Arc::clone(&record_arc));
        self.source_index.entry(source).or_default().push(id);
        self.target_index.entry(target).or_default().push(id);

        // Append to ring buffer and evict oldest if capacity exceeded
        let mut records = self.records.write();
        if records.len() >= self.max_capacity
            && let Some(old) = records.pop_front()
        {
            self.by_id.remove(&old.id);
            if let Some(mut src_entry) = self.source_index.get_mut(&old.source) {
                src_entry.retain(|&i| i != old.id);
            }
            if let Some(mut tgt_entry) = self.target_index.get_mut(&old.target) {
                tgt_entry.retain(|&i| i != old.id);
            }
        }
        records.push_back(Arc::clone(&record_arc));

        log::debug!(
            target: "system_interaction",
            "Interaction recorded: ID {id}, Kind: {:?}, Source: {:?} -> Target: {:?}",
            record_arc.kind,
            source,
            target
        );

        record_arc
    }

    /// Returns all interaction records targeting a specific entity.
    ///
    /// # Arguments
    ///
    /// * `target` - Target entity to filter by.
    ///
    /// # Returns
    ///
    /// A vector of incoming interaction records.
    pub fn inbound(&self, target: EntityId) -> Vec<Arc<InteractionRecord>> {
        let Some(ids) = self.target_index.get(&target) else {
            return Vec::new();
        };

        ids.iter()
            .filter_map(|id| self.by_id.get(id).map(|e| Arc::clone(e.value())))
            .collect()
    }

    /// Alias for `inbound`.
    ///
    /// # Arguments
    ///
    /// * `target` - Target entity.
    ///
    /// # Returns
    ///
    /// A vector of incoming interaction records.
    #[inline]
    pub fn get_inbound(&self, target: EntityId) -> Vec<Arc<InteractionRecord>> {
        self.inbound(target)
    }

    /// Returns all interaction records originated by a specific entity.
    ///
    /// # Arguments
    ///
    /// * `source` - Actor entity to filter by.
    ///
    /// # Returns
    ///
    /// A vector of outgoing interaction records.
    pub fn outbound(&self, source: EntityId) -> Vec<Arc<InteractionRecord>> {
        let Some(ids) = self.source_index.get(&source) else {
            return Vec::new();
        };

        ids.iter()
            .filter_map(|id| self.by_id.get(id).map(|e| Arc::clone(e.value())))
            .collect()
    }

    /// Alias for `outbound`.
    ///
    /// # Arguments
    ///
    /// * `source` - Actor entity.
    ///
    /// # Returns
    ///
    /// A vector of outgoing interaction records.
    #[inline]
    pub fn get_outbound(&self, source: EntityId) -> Vec<Arc<InteractionRecord>> {
        self.outbound(source)
    }

    /// Returns all code injection interactions targeting a specific process.
    ///
    /// # Arguments
    ///
    /// * `target_process` - Target process synthetic key.
    ///
    /// # Returns
    ///
    /// A vector of code injection interaction records.
    pub fn injections_into(&self, target_process: ProcessKey) -> Vec<Arc<InteractionRecord>> {
        self.inbound(EntityId::Process(target_process))
            .into_iter()
            .filter(|r| r.is_injection())
            .collect()
    }

    /// Alias for `injections_into`.
    ///
    /// # Arguments
    ///
    /// * `target_process` - Target process synthetic key.
    ///
    /// # Returns
    ///
    /// A vector of code injection interaction records.
    #[inline]
    pub fn get_injections_into(&self, target_process: ProcessKey) -> Vec<Arc<InteractionRecord>> {
        self.injections_into(target_process)
    }

    /// Returns the N most recent interactions across the entire system.
    ///
    /// # Arguments
    ///
    /// * `count` - Maximum records to retrieve.
    ///
    /// # Returns
    ///
    /// A vector of the most recent interaction records.
    pub fn recent_interactions(&self, count: usize) -> Vec<Arc<InteractionRecord>> {
        let records = self.records.read();
        records.iter().rev().take(count).cloned().collect()
    }

    /// Total count of interactions currently in the buffer.
    ///
    /// # Returns
    ///
    /// Number of active interaction records.
    #[inline]
    pub fn len(&self) -> usize {
        self.by_id.len()
    }

    /// Checks whether the interaction registry contains zero records.
    ///
    /// # Returns
    ///
    /// `true` if empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.by_id.is_empty()
    }

    /// Total count alias for backwards compatibility.
    ///
    /// # Returns
    ///
    /// Number of active interaction records.
    #[inline]
    pub fn total_count(&self) -> usize {
        self.len()
    }
}

impl Default for InteractionRegistry {
    fn default() -> Self {
        Self::new(100_000)
    }
}
