//! Callback routines invoked directly by the Windows Object Manager.

use core::sync::atomic::{AtomicU32, Ordering};
use wdk_sys::{
    _OB_PREOP_CALLBACK_STATUS, PEPROCESS, PETHREAD, POB_PRE_OPERATION_INFORMATION, PVOID,
    PsProcessType, PsThreadType,
};

use crate::domains::callbacks::filters;
use crate::wrappers;

/// Bitwise gate flags for enabling or disabling individual callback hooks dynamically.
pub(crate) const GATE_PROCESS_PROTECTION: u32 = 1 << 0;
#[allow(dead_code)]
pub(crate) const GATE_THREAD_PROTECTION: u32 = 1 << 1;

/// Global atomic gate controlling active callbacks without unregistering.
#[allow(dead_code)]
pub(crate) static CALLBACK_GATES: AtomicU32 =
    AtomicU32::new(GATE_PROCESS_PROTECTION | GATE_THREAD_PROTECTION);

/// Pre-operation callback for process handle creation and duplication.
///
/// Filters handle operations targeting protected system processes such as `lsass.exe`.
/// Emits telemetry to the per-CPU ring buffer and signals user-mode monitoring agents.
///
/// # Safety
///
/// Invoked directly by the Windows Object Manager. When non-null, `operation_information` must
/// point to a valid `OB_PRE_OPERATION_INFORMATION` structure supplied by the kernel executive.
///
/// # Arguments
///
/// * `_registration_context` - Unused registration context pointer passed during callback configuration.
/// * `operation_information` - Pointer to kernel pre-operation details.
///
/// # Return values
///
/// * `OB_PREOP_SUCCESS` - Operation inspected and allowed to proceed.
pub unsafe extern "C" fn on_pre_process_operation(
    _registration_context: PVOID,
    operation_information: POB_PRE_OPERATION_INFORMATION,
) -> wdk_sys::OB_PREOP_CALLBACK_STATUS {
    // Dynamic gate: if feature is disabled, return immediately without altering access
    if (CALLBACK_GATES.load(Ordering::Relaxed) & GATE_PROCESS_PROTECTION) == 0 {
        return _OB_PREOP_CALLBACK_STATUS::OB_PREOP_SUCCESS;
    }

    if operation_information.is_null() {
        return _OB_PREOP_CALLBACK_STATUS::OB_PREOP_SUCCESS;
    }

    // SAFETY: operation_information is verified non-null above.
    let op_info = unsafe { &mut *operation_information };

    // Skip kernel-mode callers to prevent OS deadlocks
    let is_kernel_handle = unsafe { op_info.__bindgen_anon_1.__bindgen_anon_1.KernelHandle() != 0 };
    if is_kernel_handle {
        return _OB_PREOP_CALLBACK_STATUS::OB_PREOP_SUCCESS;
    }

    let target_process_raw: PEPROCESS = unsafe {
        match op_info.ObjectType {
            obj if obj == *PsProcessType => op_info.Object as PEPROCESS,
            obj if obj == *PsThreadType => {
                // Target is an ETHREAD, resolve to parent process
                wdk_sys::ntddk::PsGetThreadProcess(op_info.Object as PETHREAD)
            }
            _ => return _OB_PREOP_CALLBACK_STATUS::OB_PREOP_SUCCESS,
        }
    };

    let current_process = wrappers::Eprocess::current();
    let target_process = match unsafe { wrappers::Eprocess::from_raw(target_process_raw) } {
        Some(proc) => proc,
        None => return _OB_PREOP_CALLBACK_STATUS::OB_PREOP_SUCCESS,
    };

    // Skip processes trying to open a handle to themselves
    if target_process.pid() == current_process.pid() {
        return _OB_PREOP_CALLBACK_STATUS::OB_PREOP_SUCCESS;
    }

    // Dispatch to process-specific filters:
    if filters::lsass::is_authentic_lsass(&target_process) {
        filters::lsass::handle_lsass_pre_operation(&current_process, &target_process, op_info);
    }

    _OB_PREOP_CALLBACK_STATUS::OB_PREOP_SUCCESS
}
