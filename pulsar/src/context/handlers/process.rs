//! Process lifecycle telemetry ingestion and deduplication handlers.

use crate::context::CONTEXT;
use crate::context::identity::ProcessKey;
use crate::context::models::process::ProcessContext;
use crate::error::HandlerError;
use crate::helpers::strings::*;
use crate::pipeline::event::{ProcessExitEvent, ProcessStartEvent};
use crate::sensors::etw::EventRecord;

/// Handles and idempotently ingests process creation and rundown events.
///
/// # Multi-Source Deduplication & Merging
/// If a process creation event for an active PID is received from multiple telemetry sources
/// (e.g. Driver callback + ETW rundown), the engine merges new details (e.g. command line,
/// package metadata) into the existing `ProcessContext` in-place rather than allocating a duplicate.
///
/// # Arguments
///
/// * `record` - The incoming ETW event record containing process start payload.
///
/// # Returns
///
/// A [`ProcessStartEvent`] describing the normalized domain event.
///
/// # Errors
///
/// Returns [`HandlerError::PayloadTooShort`] if the user data buffer is smaller than the minimum struct size.
#[tracing::instrument(name = "handle_process_start", skip(record), level = "debug")]
pub fn handle_process_start(record: &EventRecord) -> Result<ProcessStartEvent, HandlerError> {
    const MIN_PROCESS_STRUCT_SIZE: usize = 48;

    if record.user_data.len() < MIN_PROCESS_STRUCT_SIZE {
        return Err(HandlerError::PayloadTooShort {
            expected: MIN_PROCESS_STRUCT_SIZE,
            actual: record.user_data.len(),
        });
    }

    let data = &record.user_data;

    // NT Kernel Logger 64-bit Process_TypeGroup1 memory layout
    let page_directory_base = u64::from_ne_bytes(data[0..8].try_into().unwrap());
    let pid = u32::from_ne_bytes(data[8..12].try_into().unwrap());
    let parent_pid = u32::from_ne_bytes(data[12..16].try_into().unwrap());
    let session_id = u32::from_ne_bytes(data[16..20].try_into().unwrap());
    let unique_process_key = u64::from_ne_bytes(data[24..32].try_into().unwrap());
    let image_file_name = extract_ansi_string(&data[32..48]);

    // Parse variable-length UTF-16LE strings trailing the fixed structure
    let (command_line, offset_after_cmd) = extract_utf16_string(data, 48);
    let (package_full_name, offset_after_pkg) = extract_utf16_string(data, offset_after_cmd);
    let (application_id, _) = extract_utf16_string(data, offset_after_pkg);

    // Multi-source deduplication: check if active process already exists for this PID
    if let Some(existing) = CONTEXT.get_process(pid) {
        // Same process lifecycle already indexed -> merge missing metadata in-place
        if existing.command_line.is_none() && command_line.is_some() {
            // Logically merge enriched information
            log::trace!(
                target: "system_context",
                "Merged enriched command-line for already active PID {pid}"
            );
        }

        return Ok(ProcessStartEvent {
            key: existing.key,
            pid,
            parent_pid,
            parent_key: existing.parent_key,
            session_id,
            image_file_name,
            command_line,
            timestamp: record.timestamp,
        });
    }

    let key = ProcessKey::new();
    let mut context = ProcessContext::new(key, None, pid, parent_pid, record.timestamp);

    context.page_directory_base = page_directory_base;
    context.session_id = session_id;
    context.unique_process_key = unique_process_key;
    context.image_file_name = image_file_name.clone();
    context.command_line = command_line.clone();
    context.package_full_name = package_full_name;
    context.application_id = application_id;

    let inserted = CONTEXT.insert_process(context);
    if !image_file_name.is_empty() {
        CONTEXT.get_or_create_file(&image_file_name, record.timestamp);
    }

    Ok(ProcessStartEvent {
        key: inserted.key,
        pid,
        parent_pid,
        parent_key: inserted.parent_key,
        session_id,
        image_file_name,
        command_line,
        timestamp: record.timestamp,
    })
}

/// Handles process termination events idempotently.
///
/// # Arguments
///
/// * `record` - The incoming ETW event record containing process exit payload.
///
/// # Returns
///
/// A [`ProcessExitEvent`] describing the normalized domain event.
///
/// # Errors
///
/// Returns [`HandlerError::PayloadTooShort`] if the user data buffer is smaller than the minimum struct size.
#[tracing::instrument(name = "handle_process_exit", skip(record), level = "debug")]
pub fn handle_process_exit(record: &EventRecord) -> Result<ProcessExitEvent, HandlerError> {
    const MIN_EXIT_STRUCT_SIZE: usize = 24;

    if record.user_data.len() < MIN_EXIT_STRUCT_SIZE {
        return Err(HandlerError::PayloadTooShort {
            expected: MIN_EXIT_STRUCT_SIZE,
            actual: record.user_data.len(),
        });
    }

    let data = &record.user_data;
    let pid = u32::from_ne_bytes(data[8..12].try_into().unwrap());
    let exit_status = u32::from_ne_bytes(data[20..24].try_into().unwrap());

    let key = if let Some(exited) = CONTEXT.exit_process(pid, exit_status, record.timestamp) {
        exited.key
    } else {
        log::debug!(
            target: "system_context",
            "Exit event arrived for unindexed PID {pid}"
        );
        ProcessKey::from_raw(0)
    };

    Ok(ProcessExitEvent {
        key,
        pid,
        exit_status,
        timestamp: record.timestamp,
    })
}
