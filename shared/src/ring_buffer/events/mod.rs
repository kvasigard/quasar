//! Domain event payloads for shared memory ring buffer telemetry.
//!
//! Submodules organize specific kernel callback and hook domains:
//! - [`lsass`]: Object Manager handle operations targeting `lsass.exe` ([`LsassAccessEvent`]).
//! - [`handle`]: Backwards-compatible alias for [`lsass`].

pub mod handle;
pub mod lsass;

pub use lsass::*;
