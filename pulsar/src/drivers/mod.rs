//! Driver lifecycle and control management.
//!
//! This module is responsible for orchestrating the kernel-mode components of the EDR.
//! It handles the loading, configuration, health monitoring, and unloading of drivers
//! (such as the ELAM driver, file minifilters, and WFP network callouts) via the Windows
//! Service Control Manager (SCM) or the Filter Manager.
//!
//! **Important Architectural Note:**
//! This module acts strictly as the **control plane**. It should only issue commands to
//! the kernel (e.g., sending AM-PPL signature updates via IOCTLs, or starting/stopping a service).
//! It must *not* be used to read telemetry or handle event streams—those responsibilities
//! belong to the `sensors` and `comm` modules.

pub mod error;
pub mod kmdf;
pub mod scm;

pub use error::DriverError;
