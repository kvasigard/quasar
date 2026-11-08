//! Contextual telemetry enrichment subsystem.
//!
//! Bridges raw kernel and ETW event DTOs with [`SystemState`](crate::state::SystemState),
//! reconstructing process tree lineage, user token security identifiers, and decoding
//! technical operation parameters into rich domain models for rule evaluation.

pub mod lsass;
pub mod pe;
pub mod signature;

pub use lsass::{EnrichedLsassAccessEvent, decode_handle_rights, enrich_lsass_access};
