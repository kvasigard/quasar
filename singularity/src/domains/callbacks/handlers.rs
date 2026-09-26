//! Callback routines invoked directly by the Windows Object Manager.

use core::sync::atomic::{AtomicU32, Ordering};
use shared::ring_buffer::HandlePreOpEvent;
use wdk_sys::{
    _OB_PREOP_CALLBACK_STATUS, ACCESS_MASK, OB_OPERATION_HANDLE_CREATE,
    OB_OPERATION_HANDLE_DUPLICATE, PEPROCESS, PETHREAD, POB_PRE_OPERATION_INFORMATION, PVOID,
    PsProcessType, PsThreadType,
};

use crate::comm::ring_buffer;
use crate::wrappers;

/// Bitwise gate flags for enabling or disabling individual callback hooks dynamically.
pub const GATE_PROCESS_PROTECTION: u32 = 1 << 0;
pub const GATE_THREAD_PROTECTION: u32 = 1 << 1;

/// Global atomic gate controlling active callbacks without unregistering.
pub static CALLBACK_GATES: AtomicU32 =
    AtomicU32::new(GATE_PROCESS_PROTECTION | GATE_THREAD_PROTECTION);

/// Pre-operation callback for process and thread handle creation and duplication.
pub unsafe extern "system" fn on_pre_process_operation(
    _registration_context: PVOID,
    operation_information: POB_PRE_OPERATION_INFORMATION,
) -> wdk_sys::OB_PREOP_CALLBACK_STATUS {
    if operation_information.is_null() {
        return _OB_PREOP_CALLBACK_STATUS::OB_PREOP_SUCCESS;
    }

    // SAFETY: operation_information is verified non-null and remains valid
    // for the synchronous execution of this pre-operation callback.
    let op_info = unsafe { &*operation_information };

    // Evaluate active gates based on the target object type (Process vs Thread)
    let gate = CALLBACK_GATES.load(Ordering::Relaxed);
    let is_process = unsafe { op_info.ObjectType == *PsProcessType };
    let is_thread = unsafe { op_info.ObjectType == *PsThreadType };

    if (is_process && (gate & GATE_PROCESS_PROTECTION) == 0)
        || (is_thread && (gate & GATE_THREAD_PROTECTION) == 0)
        || (!is_process && !is_thread)
    {
        return _OB_PREOP_CALLBACK_STATUS::OB_PREOP_SUCCESS;
    }

    // Skip kernel-mode callers to prevent OS deadlocks and avoid high-volume internal handle noise
    let is_kernel_handle = unsafe { op_info.__bindgen_anon_1.__bindgen_anon_1.KernelHandle() != 0 };
    if is_kernel_handle {
        return _OB_PREOP_CALLBACK_STATUS::OB_PREOP_SUCCESS;
    }

    let target_process_raw: PEPROCESS = unsafe {
        if is_process {
            op_info.Object as PEPROCESS
        } else if is_thread {
            // Target is an ETHREAD, resolve to parent process
            wdk_sys::ntddk::PsGetThreadProcess(op_info.Object as PETHREAD)
        } else {
            return _OB_PREOP_CALLBACK_STATUS::OB_PREOP_SUCCESS;
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

    // TODO: Replace short_name() string comparison with dynamic LSASS PID matching.
    // EPROCESS.ImageFileName (short_name) is truncated to 15 bytes and vulnerable to name spoofing
    // by arbitrary user-mode executables named lsass.exe. Instead, cache the authentic system
    // LSASS PID during early driver initialization / PsSetCreateProcessNotifyRoutineEx and verify
    // target_process.pid() == cached_lsass_pid. In the future, this will also integrate with Rhai
    // scripting for dynamic rule-based whitelisting and alert filtering.
    if target_process
        .short_name()
        .to_bytes()
        .eq_ignore_ascii_case(b"lsass.exe")
    {
        let Some(desired_access) = extract_desired_access(op_info) else {
            return _OB_PREOP_CALLBACK_STATUS::OB_PREOP_SUCCESS;
        };

        let event = HandlePreOpEvent::new(
            current_process.pid() as u32,
            target_process.pid() as u32,
            desired_access,
            op_info.Operation as u8,
            current_process.short_name().to_bytes(),
        );

        if let Err(error) = ring_buffer::push_event(&event) {
            crate::driver_debug!(
                "[callback::handlers] Failed to enqueue HandlePreOpEvent: {error}"
            );
        }
    }

    _OB_PREOP_CALLBACK_STATUS::OB_PREOP_SUCCESS
}

/// Extracts the requested access mask from the pre-operation parameters based on the operation type.
///
/// Uses `OriginalDesiredAccess` rather than `DesiredAccess` so telemetry captures the raw permissions
/// requested by the calling process even if higher-altitude filters have already modified `DesiredAccess`.
#[inline(always)]
fn extract_desired_access(op_info: &wdk_sys::_OB_PRE_OPERATION_INFORMATION) -> Option<ACCESS_MASK> {
    if op_info.Parameters.is_null() {
        return None;
    }

    // SAFETY:
    // The Windows Object Manager guarantees `op_info.Parameters` is a non-null, valid pointer
    // for the synchronous duration of the pre-operation callback routine.
    let access = unsafe {
        match op_info.Operation {
            OB_OPERATION_HANDLE_CREATE => {
                (*op_info.Parameters)
                    .CreateHandleInformation
                    .OriginalDesiredAccess
            }
            OB_OPERATION_HANDLE_DUPLICATE => {
                (*op_info.Parameters)
                    .DuplicateHandleInformation
                    .OriginalDesiredAccess
            }
            _ => return None,
        }
    };

    Some(access)
}
