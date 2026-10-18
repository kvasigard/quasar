//! IRQL inspection and validation utilities.
//!
//! Provides zero-cost inline helpers to query and assert the processor's
//! Interrupt Request Level (IRQL) against subsystem constraints, along with
//! an RAII guard to temporarily raise IRQL to `DISPATCH_LEVEL`.

use wdk_sys::{
    DISPATCH_LEVEL, KIRQL,
    ntddk::{KeGetCurrentIrql, KeLowerIrql, KfRaiseIrql},
};

/// Queries the current processor Interrupt Request Level (IRQL).
///
/// Executes `KeGetCurrentIrql` to retrieve the hardware/architectural IRQL without side effects.
///
/// # Return values
///
/// * `u8` - Numeric IRQL value of the calling thread.
#[inline(always)]
pub(crate) fn current_irql() -> u8 {
    // SAFETY: KeGetCurrentIrql is safe to execute at any IRQL and has no preconditions or state mutations.
    unsafe { KeGetCurrentIrql() }
}

/// Verifies that the current processor IRQL is less than or equal to `max_allowed`.
///
/// Inspects the processor's current IRQL and validates that it does not exceed the supplied threshold.
///
/// # Arguments
///
/// * `max_allowed` - Maximum permissible IRQL for the requested operation.
///
/// # Return values
///
/// * `Ok(u8)` - Current IRQL when within the permissible range.
/// * `Err(u8)` - Current IRQL when exceeding `max_allowed`.
#[inline(always)]
pub(crate) fn ensure_max_irql(max_allowed: u8) -> Result<u8, u8> {
    let current = current_irql();
    if current <= max_allowed {
        Ok(current)
    } else {
        Err(current)
    }
}

/// RAII guard that raises the processor's IRQL to `DISPATCH_LEVEL` and lowers it on drop.
///
/// ### Why Raise to `DISPATCH_LEVEL` for Per-CPU SPSC Buffers?
/// In a partitioned per-CPU ring buffer, cross-core contention is completely eliminated
/// because each core writes exclusively to its own partition. However, multiple threads
/// running at `PASSIVE_LEVEL` could be scheduled on the *same* CPU core.
///
/// Raising IRQL to `DISPATCH_LEVEL` instructs the Windows thread scheduler to suspend
/// thread preemption on that specific CPU core. This guarantees mutual exclusion among all
/// threads on that core for the duration of the critical section without using spinlocks
/// or multi-producer CAS loops.
pub(crate) struct DispatchIrqlGuard {
    old_irql: KIRQL,
    raised: bool,
}

impl DispatchIrqlGuard {
    /// Ensures the processor IRQL is at least `DISPATCH_LEVEL` and returns an RAII guard.
    ///
    /// If the processor is currently below `DISPATCH_LEVEL`, raises IRQL to `DISPATCH_LEVEL`
    /// and saves the previous IRQL to restore it upon drop. If already at or above `DISPATCH_LEVEL`,
    /// leaves IRQL unchanged to prevent `IRQL_NOT_GREATER_OR_EQUAL` bugchecks.
    ///
    /// # Return values
    ///
    /// * `Self` - RAII guard holding the previous IRQL state.
    #[inline(always)]
    pub(crate) fn raise() -> Self {
        let current = current_irql();
        if current < DISPATCH_LEVEL as u8 {
            let old_irql = unsafe { KfRaiseIrql(DISPATCH_LEVEL as KIRQL) };
            Self {
                old_irql,
                raised: true,
            }
        } else {
            Self {
                old_irql: current,
                raised: false,
            }
        }
    }
}

impl Drop for DispatchIrqlGuard {
    #[inline(always)]
    fn drop(&mut self) {
        if self.raised {
            unsafe {
                KeLowerIrql(self.old_irql);
            }
        }
    }
}
