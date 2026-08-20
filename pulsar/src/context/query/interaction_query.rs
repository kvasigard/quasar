//! Fluent interaction query builder and filtering interface.

use std::sync::Arc;

use crate::context::identity::{EntityId, ProcessKey};
use crate::context::models::interaction::InteractionRecord;
use crate::context::SystemContext;

/// Fluent query builder for filtering and inspecting cross-entity interactions.
pub struct InteractionQuery<'a> {
    ctx: &'a SystemContext,
}

impl<'a> InteractionQuery<'a> {
    /// Creates a new interaction query handle.
    ///
    /// # Arguments
    ///
    /// * `ctx` - Reference to the root [`SystemContext`].
    ///
    /// # Returns
    ///
    /// An [`InteractionQuery`] builder.
    pub fn new(ctx: &'a SystemContext) -> Self {
        Self { ctx }
    }

    /// Queries all code injection interactions targeting a specific process.
    ///
    /// # Arguments
    ///
    /// * `target_process` - Target process key.
    ///
    /// # Returns
    ///
    /// An iterator over matching injection [`InteractionRecord`] items.
    pub fn injections_into(&self, target_process: ProcessKey) -> impl Iterator<Item = Arc<InteractionRecord>> {
        self.ctx.interactions.injections_into(target_process).into_iter()
    }

    /// Queries all interactions originated by a specific process.
    ///
    /// # Arguments
    ///
    /// * `source_process` - Originator process key.
    ///
    /// # Returns
    ///
    /// An iterator over matching outgoing [`InteractionRecord`] items.
    pub fn by_source_process(&self, source_process: ProcessKey) -> impl Iterator<Item = Arc<InteractionRecord>> {
        self.ctx
            .interactions
            .outbound(EntityId::Process(source_process))
            .into_iter()
    }

    /// Queries all interactions targeting a specific entity.
    ///
    /// # Arguments
    ///
    /// * `target` - Target entity identifier.
    ///
    /// # Returns
    ///
    /// An iterator over matching incoming [`InteractionRecord`] items.
    pub fn targeting(&self, target: EntityId) -> impl Iterator<Item = Arc<InteractionRecord>> {
        self.ctx.interactions.inbound(target).into_iter()
    }

    /// Returns the N most recent interactions across the entire system.
    ///
    /// # Arguments
    ///
    /// * `count` - Maximum count of recent records to retrieve.
    ///
    /// # Returns
    ///
    /// A vector of the most recent [`InteractionRecord`] items.
    pub fn recent(&self, count: usize) -> Vec<Arc<InteractionRecord>> {
        self.ctx.interactions.recent_interactions(count)
    }

    /// Returns all recent interactions matching a custom predicate.
    ///
    /// # Arguments
    ///
    /// * `max_inspect` - Maximum recent items to evaluate against the predicate.
    /// * `predicate` - Filter closure returning `true` for matching items.
    ///
    /// # Returns
    ///
    /// A vector of matching [`InteractionRecord`] items.
    pub fn matching<F>(&self, max_inspect: usize, mut predicate: F) -> Vec<Arc<InteractionRecord>>
    where
        F: FnMut(&InteractionRecord) -> bool,
    {
        self.recent(max_inspect)
            .into_iter()
            .filter(|r| predicate(r))
            .collect()
    }
}
