//! Callback routines invoked directly by the Windows Object Manager.

use core::sync::atomic::{AtomicU32, Ordering};
use wdk_sys::{
    _OB_PREOP_CALLBACK_STATUS, ACCESS_MASK, OB_OPERATION_HANDLE_CREATE,
    OB_OPERATION_HANDLE_DUPLICATE, PEPROCESS, PETHREAD, POB_PRE_OPERATION_INFORMATION, PVOID,
    PsProcessType, PsThreadType,
};

use crate::{driver_info, wrappers};

/// Bitwise gate flags for enabling or disabling individual callback hooks dynamically.
pub const GATE_PROCESS_PROTECTION: u32 = 1 << 0;
pub const GATE_THREAD_PROTECTION: u32 = 1 << 1;

/// Global atomic gate controlling active callbacks without unregistering.
pub static CALLBACK_GATES: AtomicU32 =
    AtomicU32::new(GATE_PROCESS_PROTECTION | GATE_THREAD_PROTECTION);

/// Pre-operation callback for process handle creation and duplication.
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

    // SAFETY: operation_information is not null
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

    // TODO: Expand this check to a list of processes to be monitored
    if target_process.short_name().to_bytes_with_nul() == b"lsass.exe\0" {
        let _desired_access: ACCESS_MASK = match op_info.Operation {
            OB_OPERATION_HANDLE_CREATE => unsafe {
                (*op_info.Parameters).CreateHandleInformation.DesiredAccess
            },
            OB_OPERATION_HANDLE_DUPLICATE => unsafe {
                (*op_info.Parameters)
                    .DuplicateHandleInformation
                    .DesiredAccess
            },
            _ => return _OB_PREOP_CALLBACK_STATUS::OB_PREOP_SUCCESS,
        };

        // TODO:
        // The idea is to raise an alert if a process is trying to open a handle to LSASS process and send it to
        // the usermode process. How is yet to be defined. In the future we might want to use rhai to perform
        // filtering on FP and whitelisting. The alert shall be sent only once per process.
    }

    _OB_PREOP_CALLBACK_STATUS::OB_PREOP_SUCCESS
}
