//! Anti-tampering and process protection domain.

pub(crate) mod error;
pub(crate) mod ppl;

pub(crate) use error::AntiTamperingError;
pub(crate) use ppl::change_process_ppl;
