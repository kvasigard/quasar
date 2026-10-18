//! Process handle filtering and telemetry generation for `lsass.exe`.
//!
//! Intercepts handle operations targeting the authentic Windows Local Security Authority
//! Subsystem Service (`lsass.exe`) to detect and neutralize credential dumping attempts.

use core::sync::atomic::{AtomicU32, Ordering};
use shared::ring_buffer::LsassAccessEvent;
use wdk_sys::{
    OB_OPERATION_HANDLE_CREATE, OB_OPERATION_HANDLE_DUPLICATE, _OB_PRE_OPERATION_INFORMATION,
};

use crate::domains::callbacks::operations::extract_desired_access;
use crate::wrappers::{self, PsProtectedSigner};

/// Sensitive process access rights commonly requested during credential dumping,
/// memory tampering, process forking, or handle theft targeting `lsass.exe`:
///
/// - `0x0001`: `PROCESS_TERMINATE` (terminating LSASS to trigger BSOD / DoS)
/// - `0x0002`: `PROCESS_CREATE_THREAD` (code/DLL injection into LSASS)
/// - `0x0008`: `PROCESS_VM_OPERATION` (modifying memory page attributes / VirtualAllocEx)
/// - `0x0010`: `PROCESS_VM_READ` (reading LSASS memory pages containing logon credentials)
/// - `0x0020`: `PROCESS_VM_WRITE` (in-memory patching, e.g. WDigest downgrade)
/// - `0x0040`: `PROCESS_DUP_HANDLE` (handle cloning / handle stealing attacks)
/// - `0x0080`: `PROCESS_CREATE_PROCESS` (process forking / snapshotting, e.g. Nanodump)
/// - `0x0200`: `PROCESS_SET_INFORMATION` (modifying process security / mitigation policies)
/// - `0x0800`: `PROCESS_SUSPEND_RESUME` (suspending LSASS threads during memory dump)
/// - `0x0004_0000`: `WRITE_DAC` (overwriting process security descriptor DACL)
/// - `0x0008_0000`: `WRITE_owner` (taking ownership of LSASS object)
pub(crate) const PROCESS_SENSITIVE_RIGHTS: u32 =
    0x0001 | 0x0002 | 0x0008 | 0x0010 | 0x0020 | 0x0040 | 0x0080 | 0x0200 | 0x0800 | 0x0004_0000 | 0x0008_0000;

/// Sensitive thread access rights targeting threads inside `lsass.exe`:
///
/// - `0x0001`: `THREAD_TERMINATE`
/// - `0x0002`: `THREAD_SUSPEND_RESUME`
/// - `0x0008`: `THREAD_GET_CONTEXT`
/// - `0x0010`: `THREAD_SET_CONTEXT` (APC / context hijacking)
/// - `0x0020`: `THREAD_SET_INFORMATION`
/// - `0x0100`: `THREAD_DIRECT_IMPERSONATION` (token theft via direct impersonation)
/// - `0x0200`: `THREAD_IMPERSONATE`
/// - `0x0400`: `THREAD_SET_LIMITED_INFORMATION`
/// - `0x0004_0000`: `WRITE_DAC`
/// - `0x0008_0000`: `WRITE_OWNER`
pub(crate) const THREAD_SENSITIVE_RIGHTS: u32 =
    0x0001 | 0x0002 | 0x0008 | 0x0010 | 0x0020 | 0x0100 | 0x0200 | 0x0400 | 0x0004_0000 | 0x0008_0000;

/// Standard benign query right required for basic process status querying without memory access.
pub(crate) const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;

/// Standard benign query right required for basic thread status querying.
pub(crate) const THREAD_QUERY_LIMITED_INFORMATION: u32 = 0x0800;

/// Cached Process ID of the authentic Windows Local Security Authority Subsystem Service (`lsass.exe`).
///
/// Discovered lazily upon first observation of an authentic `lsass.exe` instance in Session 0.
/// Initialized to 0 (unresolved).
pub(crate) static CACHED_LSASS_PID: AtomicU32 = AtomicU32::new(0);

/// Evaluates whether the target process is the authentic Windows LSASS instance.
///
/// Fast path: Performs an $O(1)$ atomic integer comparison against `CACHED_LSASS_PID`.
/// Slow path: Upon first encounter of a process named `lsass.exe`, verifies that it resides
/// in Terminal Services Session 0 and possesses a valid Microsoft or higher Code Integrity
/// signature before caching its PID.
///
/// # Arguments
///
/// * `target_process` - Reference to the target process wrapper.
///
/// # Return values
///
/// * `true` - Target process is the authentic LSASS instance.
/// * `false` - Target process is not LSASS.
#[inline]
pub(crate) fn is_authentic_lsass(target_process: &wrappers::Eprocess) -> bool {
    let target_pid = target_process.pid() as u32;
    let cached = CACHED_LSASS_PID.load(Ordering::Acquire);

    // Fast-path: O(1) integer comparison against cached PID (< 1ns)
    if cached != 0 && target_pid == cached {
        return true;
    }

    // Slow-path: Check short image name, Session 0 invariant, and Microsoft signature
    if target_process
        .short_name()
        .to_bytes()
        .eq_ignore_ascii_case(b"lsass.exe")
    {
        if target_process.session_id() == 0
            && target_process.signature_level().is_microsoft_or_higher()
        {
            CACHED_LSASS_PID.store(target_pid, Ordering::Release);
            crate::driver_debug!(
                "[callbacks::lsass::is_authentic_lsass] Verified and cached authentic LSASS PID: {target_pid}"
            );
            return true;
        } else {
            crate::driver_warn!(
                "[callbacks::lsass::is_authentic_lsass] Rejected unverified or non-Session 0 process named lsass.exe PID: {target_pid}, Session: {}, Sig: {:#04X}",
                target_process.session_id(),
                target_process.signature_level().0
            );
        }
    }

    false
}

/// Evaluates whether the calling process is an authorized operating system entity
/// permitted to acquire sensitive access rights to `lsass.exe`.
///
/// An access request is considered authentic and authorized if the caller possesses a verified
/// Microsoft or Windows operating system digital signature (`is_microsoft_or_higher()`) AND either:
/// 1. The caller is a protected process (PP or PPL) with an authorized signer tier
///    (`Lsa`, `Windows`, `WinTcb`, or `Antimalware`), OR
/// 2. The caller runs under `NT AUTHORITY\SYSTEM` integrity.
///
/// # Arguments
///
/// * `process` - Reference to the calling process wrapper.
///
/// # Return values
///
/// * `true` - Caller is an authorized operating system subsystem or security agent.
/// * `false` - Caller is unauthorized, untrusted, or operating outside system clearance.
#[inline]
pub(crate) fn is_authorized_caller(process: &wrappers::Eprocess) -> bool {
    let sig_level = process.signature_level();
    if !sig_level.is_microsoft_or_higher() {
        return false;
    }

    let protection = process.protection();

    // Fast-path: Check kernel PPL/PP protection with an authorized signer tier
    if protection.is_protected() {
        match protection.signer() {
            PsProtectedSigner::Lsa
            | PsProtectedSigner::Windows
            | PsProtectedSigner::WinTcb
            | PsProtectedSigner::Antimalware => return true,
            _ => {}
        }
    }

    // Secondary path: Core Windows SYSTEM services (e.g. services.exe, svchost.exe)
    let integrity = process.integrity_level();
    integrity.is_system_or_higher()
}

/// Strips sensitive access rights from the caller's requested access mask in-flight.
///
/// Modifies the `DesiredAccess` field in the Object Manager's pre-operation parameters
/// by masking out `rights_to_strip`. Only falls back to `fallback_query_right` when the
/// stripped mask would otherwise become `0`.
///
/// # Arguments
///
/// * `op_info` - Mutable reference to the Object Manager pre-operation details structure.
/// * `rights_to_strip` - Bitmask of sensitive permissions to remove.
/// * `fallback_query_right` - Minimal query permission if the resulting mask is zero.
///
/// # Return values
///
/// * `u32` - The resulting granted access mask post-mitigation, or 0 if parameters are null.
#[inline(always)]
pub(crate) fn strip_sensitive_access(
    op_info: &mut _OB_PRE_OPERATION_INFORMATION,
    rights_to_strip: u32,
    fallback_query_right: u32,
) -> u32 {
    if op_info.Parameters.is_null() {
        return 0;
    }

    unsafe {
        match op_info.Operation {
            OB_OPERATION_HANDLE_CREATE => {
                let mask = &mut (*op_info.Parameters).CreateHandleInformation.DesiredAccess;
                *mask &= !rights_to_strip;
                if *mask == 0 {
                    *mask = fallback_query_right;
                }
                *mask
            }
            OB_OPERATION_HANDLE_DUPLICATE => {
                let mask = &mut (*op_info.Parameters).DuplicateHandleInformation.DesiredAccess;
                *mask &= !rights_to_strip;
                if *mask == 0 {
                    *mask = fallback_query_right;
                }
                *mask
            }
            _ => 0,
        }
    }
}

/// Handles pre-operation inspection, in-flight mitigation, and telemetry emission for requests targeting `lsass.exe`.
///
/// Extracts requested access rights, logs debug information when sensitive permissions are requested,
/// verifies caller (and duplicate target process) authenticity against PPL and token integrity gates,
/// strips unauthorized sensitive rights, and pushes telemetry to the lock-free ring buffer.
///
/// # Arguments
///
/// * `current_process` - Wrapper around the calling process requesting the handle.
/// * `target_process` - Wrapper around the authentic LSASS target process.
/// * `op_info` - Mutable reference to the Object Manager pre-operation details structure.
/// * `is_thread_handle` - `true` if the handle targets an `ETHREAD` inside LSASS, `false` for `EPROCESS`.
pub(crate) fn handle_lsass_pre_operation(
    current_process: &wrappers::Eprocess,
    target_process: &wrappers::Eprocess,
    op_info: &mut _OB_PRE_OPERATION_INFORMATION,
    is_thread_handle: bool,
) {
    let Some(desired_access) = extract_desired_access(op_info) else {
        return;
    };

    let (sensitive_rights, fallback_query_right) = if is_thread_handle {
        (THREAD_SENSITIVE_RIGHTS, THREAD_QUERY_LIMITED_INFORMATION)
    } else {
        (PROCESS_SENSITIVE_RIGHTS, PROCESS_QUERY_LIMITED_INFORMATION)
    };

    // Filter out benign non-sensitive operations (e.g. basic PROCESS_QUERY_LIMITED_INFORMATION)
    if (desired_access & sensitive_rights) == 0 {
        return;
    }

    // For handle duplication, also verify that the destination process receiving the duplicated handle is authorized
    let dup_target_authorized = if op_info.Operation == OB_OPERATION_HANDLE_DUPLICATE
        && !op_info.Parameters.is_null()
    {
        let dup_target_raw = unsafe {
            (*op_info.Parameters)
                .DuplicateHandleInformation
                .TargetProcess as wdk_sys::PEPROCESS
        };
        match unsafe { wrappers::Eprocess::from_raw(dup_target_raw) } {
            Some(dup_target) => {
                dup_target.pid() == target_process.pid() || is_authorized_caller(&dup_target)
            }
            None => false,
        }
    } else {
        true
    };

    let caller_sig_level = current_process.signature_level();
    let caller_integrity = current_process.integrity_level();
    let caller_protection = current_process.protection();

    crate::driver_debug!(
        "[callbacks::lsass] Sensitive handle request to LSASS: PID {} [Sig: {:#04X}, Integrity: {:#06X}, PPL: {:#04X}] : Target PID {}, DesiredAccess: {:#010X}",
        current_process.pid(),
        caller_sig_level.0,
        caller_integrity.0,
        caller_protection.0,
        target_process.pid(),
        desired_access
    );

    // Skip authentic operating system components and protected subsystems only if both caller and destination are authorized
    if is_authorized_caller(current_process) && dup_target_authorized {
        return;
    }

    // Strip sensitive permissions from the requested access mask and record granted rights
    let granted_access = strip_sensitive_access(op_info, sensitive_rights, fallback_query_right);

    // Emit security incident telemetry to user-mode monitoring pipeline
    let event = LsassAccessEvent::new(
        current_process.pid() as u32,
        target_process.pid() as u32,
        desired_access,
        granted_access,
        caller_integrity.0,
        caller_sig_level.0,
        caller_protection.0,
        op_info.Operation as u8,
        current_process.short_name().to_bytes(),
    );

    if crate::comm::ring_buffer::write_driver_event(&event).is_ok() {
        crate::comm::ring_buffer::signal_reader();
    }
}
