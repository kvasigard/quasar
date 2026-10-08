//! Domain event payloads for shared memory ring buffer telemetry.
//!
//! Submodules organize specific kernel callback and hook domains:
//! - [`handle`]: Object Manager handle operations (`HandlePreOpEvent`).

pub mod handle;

pub use handle::*;
