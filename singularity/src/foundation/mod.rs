//! Foundational kernel primitives, error aggregation, logging, and memory guards.
//!
//! # Architectural Scope & Boundary Guidelines
//!
//! The `foundation` module is strictly reserved for domain-agnostic foundational utilities.
//! To prevent this module from becoming a catch-all junk drawer, code placed in `foundation`
//! must adhere to the following rules:
//!
//! * **Zero Domain Logic**: Must never contain security rules, PIDs, policy checks,
//!   or feature-specific implementations.
//! * **Low-Level Kernel Primitives**: Restricted to generic RAII guards, string helpers,
//!   leveled logging, and driver lifecycle synchronization.
//! * **Single Responsibility**: Every file in this module must address a single,
//!   isolated foundational need.

pub mod error;
pub mod log;
pub mod raii;
pub mod state;
pub mod string;

// Re-export common foundation types for driver-wide convenience
pub use error::{DeviceError, DriverError};
pub use raii::EprocessGuard;
pub use state::DRIVER_STATE;
pub use string::init_unicode_string;
