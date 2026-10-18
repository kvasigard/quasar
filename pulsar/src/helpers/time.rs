//! High-resolution timestamp utilities standardized across the Pulsar telemetry pipeline.
//!
//! All [`SystemState`](crate::state::SystemState) and [`ProcessTree`](crate::state::process_tree::ProcessTree)
//! temporal lookups operate strictly in the Windows `QueryPerformanceCounter` (QPC) tick clock domain,
//! matching the `Wnode.ClientContext = 1` configuration of the NT Kernel Logger ETW session and the
//! `KeQueryPerformanceCounter` timestamps stamped by the Singularity kernel driver.

use std::time::{SystemTime, UNIX_EPOCH};
use windows_sys::Win32::System::Performance::QueryPerformanceCounter;

/// Queries the current hardware `QueryPerformanceCounter` (QPC) tick value.
///
/// # Returns
///
/// The monotonic 64-bit QPC tick counter matching ETW and kernel driver event timestamps.
#[inline]
pub fn current_qpc_ticks() -> i64 {
    let mut ticks: i64 = 0;
    // SAFETY: Passing a valid mutable pointer to an i64 stack variable is always safe.
    unsafe {
        QueryPerformanceCounter(&raw mut ticks);
    }
    ticks
}

/// Queries the current wall-clock Unix epoch timestamp in milliseconds.
///
/// Used exclusively for human-facing alert records (`DetectionAlert`).
///
/// # Returns
///
/// Milliseconds elapsed since `UNIX_EPOCH`.
#[inline]
pub fn current_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}
