//! Actor process context enrichment and ancestral tree reconstruction.
//!
//! Queries [`SystemState`](crate::state::SystemState) to correlate OS process identifiers
//! against historical process lifetimes, extracting executable image paths, launch command lines,
//! token security identifiers (SIDs), and walking parentage back to system root.

use crate::alerts::ActorContext;
use crate::helpers::time::current_qpc_ticks;
use crate::model::types::ProcessId;
use crate::state::system_state;

/// Queries the operating system directly for the full executable image path of an active process.
///
/// Invokes `QueryFullProcessImageNameW` via a query-limited Win32 process handle. This provides
/// authoritative filesystem path resolution for processes that were initialized prior to ETW trace
/// activation or whose process creation events were dropped due to kernel event buffer saturation.
///
/// # Arguments
///
/// * `pid` - Target OS process identifier to query.
///
/// # Returns
///
/// `Some(String)` containing the normalized Win32 image path if the process is currently running
/// and query access is permitted; otherwise `None`.
#[cfg(windows)]
fn query_process_image_path(pid: u32) -> Option<String> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
    };

    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if handle.is_null() {
            return None;
        }

        let mut buffer = [0u16; 1024];
        let mut len = buffer.len() as u32;
        let success = QueryFullProcessImageNameW(handle, 0, buffer.as_mut_ptr(), &mut len);
        CloseHandle(handle);

        if success != 0 && len > 0 {
            Some(String::from_utf16_lossy(&buffer[..len as usize]))
        } else {
            None
        }
    }
}

#[cfg(not(windows))]
fn query_process_image_path(_pid: u32) -> Option<String> {
    None
}

#[cfg(windows)]
mod wintrust_ffi {
    use core::ffi::c_void;
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::core::GUID;

    pub const SIF_AUTHENTICODE_SIGNED: u32 = 0x0001;
    pub const SIF_CATALOG_SIGNED: u32 = 0x0002;
    pub const SIF_CHECK_OS_BINARY: u32 = 0x0008;
    pub const SIF_BASE_VERIFICATION: u32 = 0x0100;

    pub const SIGNATURE_STATE_VALID: i32 = 5;
    pub const SIGNATURE_STATE_TRUSTED: i32 = 6;
    pub const WTD_UI_NONE: u32 = 2;
    pub const WTD_REVOKE_NONE: u32 = 0;
    pub const WTD_CHOICE_FILE: u32 = 1;
    pub const WTD_STATEACTION_CLOSE: u32 = 2;

    #[repr(C)]
    pub struct SIGNATURE_INFO {
        pub cb_size: u32,
        pub signature_state: i32,
        pub signature_type: i32,
        pub signature_info_availability: u32,
        pub info_availability: u32,
        pub display_name: *mut u16,
        pub display_name_len: u32,
        pub publisher_name: *mut u16,
        pub publisher_name_len: u32,
        pub more_info_url: *mut u16,
        pub more_info_url_len: u32,
        pub hash_value: *mut u8,
        pub hash_value_len: u32,
        pub is_os_binary: i32,
    }

    #[repr(C)]
    pub struct WINTRUST_DATA {
        pub cb_struct: u32,
        pub policy_callback_data: *mut c_void,
        pub sip_client_data: *mut c_void,
        pub ui_choice: u32,
        pub revocation_checks: u32,
        pub union_choice: u32,
        pub union_ptr: *mut c_void,
        pub state_action: u32,
        pub state_data: HANDLE,
        pub url_reference: *mut u16,
        pub prov_flags: u32,
        pub ui_context: u32,
        pub signature_settings: *mut c_void,
    }

    pub const WINTRUST_ACTION_GENERIC_VERIFY_V2: GUID = GUID {
        data1: 0x00aac56b,
        data2: 0xcd44,
        data3: 0x11d0,
        data4: [0x8c, 0xc2, 0x00, 0xc0, 0x4f, 0xc2, 0x95, 0xee],
    };

    pub type FnWTGetSignatureInfo = unsafe extern "system" fn(
        psz_file: *const u16,
        h_file: HANDLE,
        sig_info_flags: u32,
        sig_info: *mut SIGNATURE_INFO,
        cert_context: *mut *mut c_void,
        wvt_state_data: *mut HANDLE,
    ) -> i32;

    #[link(name = "wintrust")]
    unsafe extern "system" {
        pub fn WinVerifyTrust(
            hwnd: HANDLE,
            action_id: *const GUID,
            data: *mut WINTRUST_DATA,
        ) -> i32;
    }

    #[link(name = "crypt32")]
    unsafe extern "system" {
        pub fn CertFreeCertificateContext(cert_context: *const c_void) -> i32;
    }

    pub fn resolve_wt_get_signature_info() -> Option<FnWTGetSignatureInfo> {
        use std::sync::OnceLock;
        use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};

        static FN_PTR: OnceLock<Option<FnWTGetSignatureInfo>> = OnceLock::new();
        *FN_PTR.get_or_init(|| unsafe {
            let dll = LoadLibraryW(windows_sys::w!("wintrust.dll"));
            if dll.is_null() {
                return None;
            }
            let func = GetProcAddress(dll, b"WTGetSignatureInfo\0".as_ptr())?;
            Some(core::mem::transmute(func))
        })
    }
}

/// Verifies the Authenticode or Windows Catalog signature of an executable on disk,
/// caching results by normalized lowercase path to avoid repeated cryptographic I/O.
///
/// Returns an `SeSigningLevel`-compatible byte:
/// - `12` (`WINDOWS`) if signed and verified as an authentic Windows OS binary (`fOSBinary != 0`).
/// - `8` (`MICROSOFT` / trusted Authenticode/Catalog) if signature state is valid/trusted.
/// - `0` (`UNCHECKED` / unsigned) if unsigned, untrusted, or invalid policy.
#[cfg(windows)]
pub fn verify_binary_signature_level(image_path: &str) -> u8 {
    use std::collections::HashMap;
    use std::sync::{LazyLock, RwLock};
    use windows_sys::Win32::Foundation::{CloseHandle, GENERIC_READ, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        OPEN_EXISTING,
    };
    use wintrust_ffi::*;

    static SIG_CACHE: LazyLock<RwLock<HashMap<String, u8>>> =
        LazyLock::new(|| RwLock::new(HashMap::new()));

    let key = image_path.to_lowercase();
    if let Some(&cached) = SIG_CACHE
        .read()
        .unwrap_or_else(|p| p.into_inner())
        .get(&key)
    {
        return cached;
    }

    let Some(wt_get_sig_info) = resolve_wt_get_signature_info() else {
        return 0;
    };

    let wide_path: Vec<u16> = image_path.encode_utf16().chain(Some(0)).collect();
    let level = unsafe {
        let h_file = CreateFileW(
            wide_path.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            core::ptr::null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            core::ptr::null_mut(),
        );

        if h_file == INVALID_HANDLE_VALUE || h_file.is_null() {
            0
        } else {
            let mut sig_info: SIGNATURE_INFO = core::mem::zeroed();
            sig_info.cb_size = core::mem::size_of::<SIGNATURE_INFO>() as u32;
            let mut cert_ctx: *mut core::ffi::c_void = core::ptr::null_mut();
            let mut wvt_state: windows_sys::Win32::Foundation::HANDLE = core::ptr::null_mut();

            let flags = SIF_AUTHENTICODE_SIGNED
                | SIF_CATALOG_SIGNED
                | SIF_CHECK_OS_BINARY
                | SIF_BASE_VERIFICATION;

            let hr = wt_get_sig_info(
                wide_path.as_ptr(),
                h_file,
                flags,
                &raw mut sig_info,
                &raw mut cert_ctx,
                &raw mut wvt_state,
            );

            if !wvt_state.is_null() {
                let mut wtd: WINTRUST_DATA = core::mem::zeroed();
                wtd.cb_struct = core::mem::size_of::<WINTRUST_DATA>() as u32;
                wtd.ui_choice = WTD_UI_NONE;
                wtd.revocation_checks = WTD_REVOKE_NONE;
                wtd.union_choice = WTD_CHOICE_FILE;
                wtd.state_action = WTD_STATEACTION_CLOSE;
                wtd.state_data = wvt_state;
                let action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
                let _ = WinVerifyTrust(core::ptr::null_mut(), &raw const action, &raw mut wtd);
            }

            if !cert_ctx.is_null() {
                let _ = CertFreeCertificateContext(cert_ctx);
            }

            CloseHandle(h_file);

            if hr >= 0
                && (sig_info.signature_state == SIGNATURE_STATE_VALID
                    || sig_info.signature_state == SIGNATURE_STATE_TRUSTED)
            {
                if sig_info.is_os_binary != 0 {
                    12 // SeSigningLevel::WINDOWS
                } else {
                    8 // Verified Authenticode / Catalog signature
                }
            } else {
                0
            }
        }
    };

    if level > 0 {
        let mut guard = SIG_CACHE.write().unwrap_or_else(|p| p.into_inner());
        if guard.len() < 4096 {
            guard.insert(key, level);
        }
    }

    level
}

#[cfg(not(windows))]
pub fn verify_binary_signature_level(_image_path: &str) -> u8 {
    0
}

/// Cached live process metadata snapshot queried directly from the OS.
#[derive(Debug, Clone)]
struct LiveProcessMetadata {
    image_path: String,
    command_line: String,
    user_sid: String,
    session_id: u32,
    parent_pid: u32,
    verified_sig_level: u8,
}

/// Bounded process metadata cache correlating short-lived or newly spawned processes directly
/// from the operating system when kernel driver callbacks (`ObRegisterCallbacks`) arrive before
/// asynchronous ETW trace buffers deliver `Process::Start` events to [`SystemState`].
///
/// Bounded to 4,096 entries to prevent unbounded memory growth during high process churn.
#[cfg(windows)]
static LIVE_ACTOR_CACHE: std::sync::LazyLock<
    std::sync::RwLock<std::collections::HashMap<u32, LiveProcessMetadata>>,
> = std::sync::LazyLock::new(|| std::sync::RwLock::new(std::collections::HashMap::new()));

/// Queries an active process directly via a query-limited handle to retrieve its executable path,
/// launch command line, parent process ID, session ID, and user token SID.
///
/// Operates as an out-of-band resolution fallback when an event arrives before ETW telemetry has
/// ingested the process into [`SystemState`]. Uses `ProcessCommandLineInformation` (class 60) and
/// `ProcessBasicInformation` (class 0) through `NtQueryInformationProcess` to obtain process state
/// without requesting `PROCESS_VM_READ`.
///
/// # Arguments
///
/// * `pid` - Caller OS process identifier.
///
/// # Returns
///
/// `Some(LiveProcessMetadata)` if the target process is running and permits query-limited access; otherwise `None`.
#[cfg(windows)]
fn query_live_process_metadata(pid: u32) -> Option<LiveProcessMetadata> {
    use windows_sys::Wdk::System::Threading::NtQueryInformationProcess;
    use windows_sys::Win32::Foundation::{CloseHandle, LocalFree};
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows_sys::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER};
    use windows_sys::Win32::System::RemoteDesktop::ProcessIdToSessionId;
    use windows_sys::Win32::System::Threading::{
        OpenProcess, OpenProcessToken, QueryFullProcessImageNameW,
        PROCESS_QUERY_LIMITED_INFORMATION,
    };

    #[repr(C)]
    struct UNICODE_STRING {
        length: u16,
        maximum_length: u16,
        buffer: *const u16,
    }

    #[repr(C)]
    struct PROCESS_BASIC_INFORMATION {
        exit_status: i32,
        peb_base_address: *mut core::ffi::c_void,
        affinity_mask: usize,
        base_priority: i32,
        unique_process_id: usize,
        inherited_from_unique_process_id: usize,
    }

    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if handle.is_null() {
            return None;
        }

        let mut path_buf = [0u16; 1024];
        let mut path_len = path_buf.len() as u32;
        let image_path = if QueryFullProcessImageNameW(handle, 0, path_buf.as_mut_ptr(), &mut path_len) != 0
            && path_len > 0
        {
            String::from_utf16_lossy(&path_buf[..path_len as usize])
        } else {
            CloseHandle(handle);
            return None;
        };

        let mut command_line = String::new();
        let mut cmd_buf = vec![0u8; 2048];
        let mut ret_len = 0u32;
        let mut status = NtQueryInformationProcess(
            handle,
            60, // ProcessCommandLineInformation
            cmd_buf.as_mut_ptr() as *mut core::ffi::c_void,
            cmd_buf.len() as u32,
            &mut ret_len,
        );
        // Dynamically resize buffer and retry if the initial stack buffer was insufficient for long CLI invocations
        if status != 0 && ret_len > cmd_buf.len() as u32 {
            cmd_buf.resize(ret_len as usize, 0);
            status = NtQueryInformationProcess(
                handle,
                60,
                cmd_buf.as_mut_ptr() as *mut core::ffi::c_void,
                cmd_buf.len() as u32,
                &mut ret_len,
            );
        }
        if status == 0 && ret_len >= core::mem::size_of::<UNICODE_STRING>() as u32 {
            let us = core::ptr::read_unaligned(cmd_buf.as_ptr() as *const UNICODE_STRING);
            let char_len = (us.length / 2) as usize;
            if !us.buffer.is_null() && char_len > 0 {
                let slice = core::slice::from_raw_parts(us.buffer, char_len);
                command_line = String::from_utf16_lossy(slice);
            }
        }

        let mut parent_pid = 0u32;
        let mut pbi: PROCESS_BASIC_INFORMATION = core::mem::zeroed();
        let mut pbi_len = 0u32;
        let pbi_status = NtQueryInformationProcess(
            handle,
            0, // ProcessBasicInformation
            &mut pbi as *mut _ as *mut core::ffi::c_void,
            core::mem::size_of::<PROCESS_BASIC_INFORMATION>() as u32,
            &mut pbi_len,
        );
        if pbi_status == 0 {
            parent_pid = pbi.inherited_from_unique_process_id as u32;
        }

        let mut session_id = 0u32;
        ProcessIdToSessionId(pid, &mut session_id);

        let mut user_sid = "Unknown".to_string();
        let mut token = core::ptr::null_mut();
        if OpenProcessToken(handle, TOKEN_QUERY, &mut token) != 0 && !token.is_null() {
            let mut token_buf = [0u64; 32];
            let mut token_ret_len = 0u32;
            if GetTokenInformation(
                token,
                TokenUser,
                token_buf.as_mut_ptr() as *mut _,
                core::mem::size_of_val(&token_buf) as u32,
                &mut token_ret_len,
            ) != 0
            {
                let token_user =
                    core::ptr::read_unaligned(token_buf.as_ptr() as *const TOKEN_USER);
                let mut str_ptr: *mut u16 = core::ptr::null_mut();
                if ConvertSidToStringSidW(token_user.User.Sid, &mut str_ptr) != 0 && !str_ptr.is_null() {
                    let mut len = 0;
                    while *str_ptr.add(len) != 0 {
                        len += 1;
                    }
                    let sid_slice = core::slice::from_raw_parts(str_ptr, len);
                    user_sid = String::from_utf16_lossy(sid_slice);
                    // LocalFree is required to release memory allocated by ConvertSidToStringSidW
                    LocalFree(str_ptr as *mut _);
                }
            }
            CloseHandle(token);
        }

        CloseHandle(handle);

        let verified_sig_level = verify_binary_signature_level(&image_path);

        Some(LiveProcessMetadata {
            image_path,
            command_line,
            user_sid,
            session_id,
            parent_pid,
            verified_sig_level,
        })
    }
}

#[cfg(not(windows))]
fn query_live_process_metadata(_pid: u32) -> Option<LiveProcessMetadata> {
    None
}

/// Extracts executable file path from command line arguments when process has already terminated.
fn extract_path_from_cmdline(cmdline: &str) -> Option<String> {
    let trimmed = cmdline.trim();
    if trimmed.starts_with('"') {
        if let Some(end_quote) = trimmed[1..].find('"') {
            let candidate = &trimmed[1..=end_quote];
            if candidate.contains('\\') || candidate.contains('/') {
                return Some(candidate.to_string());
            }
        }
    } else if let Some(space) = trimmed.find(' ') {
        let candidate = &trimmed[..space];
        if candidate.contains('\\') || candidate.contains('/') {
            return Some(candidate.to_string());
        }
    } else if trimmed.contains('\\') || trimmed.contains('/') {
        return Some(trimmed.to_string());
    }
    None
}

/// Resolves a contextual actor snapshot for a process identifier.
///
/// First queries [`SystemState`](crate::state::SystemState) for tracked process generations.
/// If untracked (e.g. freshly created attack process whose ETW trace buffer has not flushed yet),
/// falls back to authoritative live Win32 process interrogation and caches the result.
///
/// # Arguments
///
/// * `pid` - Caller OS process identifier.
/// * `fallback_name` - Short executable image name extracted from the kernel event header.
///
/// # Returns
///
/// An enriched [`ActorContext`] containing process metadata and lineage hierarchy.
pub fn resolve_actor_context(pid: u32, fallback_name: &str) -> ActorContext {
    let now_qpc = current_qpc_ticks();

    if let Some((node, parent_name, ancestry)) =
        system_state().resolve_actor_snapshot(ProcessId(pid), now_qpc)
    {
        let full_image_path = query_process_image_path(pid)
            .or_else(|| extract_path_from_cmdline(&node.command_line));
        let verified_sig_level = full_image_path
            .as_deref()
            .map(verify_binary_signature_level)
            .unwrap_or(0);
        let image_path = full_image_path.unwrap_or_else(|| node.image_file_name.clone());

        return ActorContext {
            pid,
            name: node.image_file_name.clone(),
            image_path,
            command_line: node.command_line.clone(),
            user_sid: node.user_sid.to_string(),
            session_id: node.session_id.0,
            integrity_level: 0,
            signature_level: verified_sig_level,
            protection: 0,
            parent_pid: node.parent.pid().0,
            parent_name,
            ancestry,
        };
    }

    #[cfg(windows)]
    let live_meta = {
        let cached = LIVE_ACTOR_CACHE
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .get(&pid)
            .cloned();
        match cached {
            Some(meta) => Some(meta),
            None => {
                let queried = query_live_process_metadata(pid);
                if let Some(ref meta) = queried {
                    let mut guard = LIVE_ACTOR_CACHE.write().unwrap_or_else(|p| p.into_inner());
                    if guard.len() < 4096 {
                        guard.insert(pid, meta.clone());
                    }
                }
                queried
            }
        }
    };

    #[cfg(not(windows))]
    let live_meta = query_live_process_metadata(pid);

    if let Some(meta) = live_meta {
        let short_name = std::path::Path::new(&meta.image_path)
            .file_name()
            .and_then(|f| f.to_str())
            .unwrap_or(fallback_name)
            .to_string();

        let cmd_line = if !meta.command_line.is_empty() {
            meta.command_line
        } else {
            meta.image_path.clone()
        };

        let (parent_name, ancestry) = if meta.parent_pid > 0 && meta.parent_pid != pid {
            if let Some((p_node, _, p_ancestry)) =
                system_state().resolve_actor_snapshot(ProcessId(meta.parent_pid), now_qpc)
            {
                let mut full_ancestry = p_ancestry;
                full_ancestry.push(format!("{short_name} ({pid})"));
                (p_node.image_file_name.clone(), full_ancestry)
            } else {
                ("Unknown".to_string(), vec![format!("{short_name} ({pid})")])
            }
        } else {
            ("Unknown".to_string(), vec![format!("{short_name} ({pid})")])
        };

        return ActorContext {
            pid,
            name: short_name,
            image_path: meta.image_path,
            command_line: cmd_line,
            user_sid: meta.user_sid,
            session_id: meta.session_id,
            integrity_level: 0,
            signature_level: meta.verified_sig_level,
            protection: 0,
            parent_pid: meta.parent_pid,
            parent_name,
            ancestry,
        };
    }

    let full_image_path = query_process_image_path(pid);
    let verified_sig_level = full_image_path
        .as_deref()
        .map(verify_binary_signature_level)
        .unwrap_or(0);
    let image_path = full_image_path.unwrap_or_else(|| fallback_name.to_string());

    ActorContext {
        pid,
        name: fallback_name.to_string(),
        image_path,
        command_line: fallback_name.to_string(),
        user_sid: "Unknown".to_string(),
        session_id: 0,
        integrity_level: 0,
        signature_level: verified_sig_level,
        protection: 0,
        parent_pid: 0,
        parent_name: "Unknown".to_string(),
        ancestry: vec![format!("{fallback_name} ({pid})")],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_system32_taskmgr_signature_level() {
        let path = "C:\\Windows\\System32\\Taskmgr.exe";
        if std::path::Path::new(path).exists() {
            let level = verify_binary_signature_level(path);
            assert!(
                level >= 8,
                "Authentic C:\\Windows\\System32\\Taskmgr.exe must resolve to signature level >= 8, got {level}"
            );
        }
    }
}
