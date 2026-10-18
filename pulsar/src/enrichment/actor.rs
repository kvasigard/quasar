//! Actor process context enrichment and ancestral tree reconstruction.
//!
//! Queries [`SystemState`](crate::state::SystemState) to correlate OS process identifiers
//! against historical process lifetimes, extracting executable image paths, launch command lines,
//! token security identifiers (SIDs), and walking parentage back to system root.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::alerts::ActorContext;
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
        OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
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

/// Resolves a contextual actor snapshot for a process identifier from `SystemState`.
///
/// Navigates the execution tree backwards from the caller PID through historical process
/// generations. If the process is untracked (e.g. spawned before telemetry collection initialized),
/// constructs a fallback snapshot using the raw binary name extracted from the kernel event header.
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
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64;

    let full_image_path = query_process_image_path(pid);

    if let Some(key) = system_state().resolve_process_key(ProcessId(pid), now_ms)
        && let Some(node) = system_state().get_process_snapshot(&key)
    {
        let mut ancestry = Vec::new();
        system_state().walk_ancestors(&key, |ancestor| {
            ancestry.push(format!("{} ({})", ancestor.image_file_name, ancestor.key.pid.0));
            true
        });

        let parent_name = node
            .parent
            .key()
            .and_then(|pk| system_state().get_process_snapshot(&pk))
            .map(|pn| pn.image_file_name)
            .unwrap_or_default();

        let image_path = full_image_path.unwrap_or_else(|| node.image_file_name.clone());

        return ActorContext {
            pid,
            name: node.image_file_name.clone(),
            image_path,
            command_line: node.command_line.clone(),
            user_sid: node.user_sid.to_string(),
            session_id: node.session_id.0,
            integrity_level: 0,
            signature_level: 0,
            protection: 0,
            parent_pid: node.parent.pid().0,
            parent_name,
            ancestry,
        };
    }

    // Fallback context if process was untracked or started before telemetry trace began
    let image_path = full_image_path.unwrap_or_else(|| fallback_name.to_string());

    ActorContext {
        pid,
        name: fallback_name.to_string(),
        image_path,
        command_line: fallback_name.to_string(),
        user_sid: "Unknown".to_string(),
        session_id: 0,
        integrity_level: 0,
        signature_level: 0,
        protection: 0,
        parent_pid: 0,
        parent_name: "Unknown".to_string(),
        ancestry: vec![format!("{fallback_name} ({pid})")],
    }
}
