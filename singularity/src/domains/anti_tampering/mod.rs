//! Anti-tampering and process protection domain.

pub mod error;
pub mod ppl;

pub use error::AntiTamperingError;
pub use ppl::change_process_ppl;
