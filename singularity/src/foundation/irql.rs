//! IRQL inspection and validation utilities.
//!
//! Provides zero-cost inline helpers to query and assert the processor's
//! Interrupt Request Level (IRQL) against subsystem constraints.

use wdk_sys::ntddk::KeGetCurrentIrql;

/// Queries the current processor Interrupt Request Level (IRQL).
#[inline(always)]
pub fn current_irql() -> u8 {
    // SAFETY: KeGetCurrentIrql is safe to execute at any IRQL and has no preconditions or state mutations.
    unsafe { KeGetCurrentIrql() }
}

/// Verifies that the current processor IRQL is less than or equal to `max_allowed`.
///
/// # Returns
/// * `Ok(current_irql)` if `current_irql <= max_allowed`
/// * `Err(current_irql)` if the processor is executing at a higher IRQL than allowed
#[inline(always)]
pub fn ensure_max_irql(max_allowed: u8) -> Result<u8, u8> {
    let current = current_irql();
    if current <= max_allowed {
        Ok(current)
    } else {
        Err(current)
    }
}
