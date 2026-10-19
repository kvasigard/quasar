//! Contextual telemetry enrichment subsystem.
//!
//! Bridges raw kernel and ETW event DTOs with [`SystemState`](crate::state::SystemState),
//! reconstructing process tree lineage, user token security identifiers, and decoding
//! technical operation parameters into rich domain models for rule evaluation.

pub mod actor;
pub mod lsass;

pub use actor::resolve_actor_context;
pub use lsass::{EnrichedLsassAccessEvent, decode_handle_rights, enrich_lsass_access};
