//! Ingestion handlers and binary parsers for NT Kernel Logger ETW telemetry.

use crate::context::TREE;
use crate::context::process::{LoadedModule, ProcessContext, ProcessKey};
use crate::helpers::strings::*;
use crate::sensors::etw::EventRecord;

/// Deserialization and resolution errors encountered during ETW payload handling.
#[derive(Debug)]
pub enum HandlerError {
    /// Payload buffer length is smaller than the required fixed structure header.
    PayloadTooShort { expected: usize, actual: usize },
    /// Process ID does not exist in the active process tree.
    ProcessNotFound(u32),
}

/// Handles process creation and rundown events (`OPCODE_PROCESS_START` / `OPCODE_PROCESS_DC_START`).
///
/// # Arguments
///
/// * `record` - The raw ETW event record containing process initialization data.
///
/// # Returns
///
/// `Ok(())` on successful insertion into `TREE`, or `Err(HandlerError)` if payload is malformed.
///
/// # Errors
///
/// Returns `HandlerError::PayloadTooShort` if the record user data is fewer than 48 bytes.
pub fn handle_process_start(record: &EventRecord) -> Result<(), HandlerError> {
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

    let key = ProcessKey::new();
    let mut context = ProcessContext::new(key, None, pid, parent_pid, record.timestamp);

    context.page_directory_base = page_directory_base;
    context.session_id = session_id;
    context.unique_process_key = unique_process_key;
    context.image_file_name = image_file_name;
    context.command_line = command_line;
    context.package_full_name = package_full_name;
    context.application_id = application_id;

    TREE.insert_process(context);
    Ok(())
}

/// Handles process termination events (`OPCODE_PROCESS_END`).
///
/// # Arguments
///
/// * `record` - The raw ETW event record containing process exit metadata.
///
/// # Returns
///
/// `Ok(())` on successful state transition, or `Err(HandlerError)` if payload is malformed.
///
/// # Errors
///
/// Returns `HandlerError::PayloadTooShort` if the record user data is fewer than 24 bytes.
pub fn handle_process_exit(record: &EventRecord) -> Result<(), HandlerError> {
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

    if TREE
        .exit_process(pid, exit_status, record.timestamp)
        .is_none()
    {
        log::debug!(
            target: "system_context",
            "Exit event arrived for unindexed PID {pid}"
        );
    }

    Ok(())
}

/// Handles module mapping events (`OPCODE_IMAGE_LOAD` / `OPCODE_IMAGE_DC_START`).
///
/// # Arguments
///
/// * `record` - The raw ETW event record containing loaded binary metadata.
///
/// # Returns
///
/// `Ok(())` on success, or `Err(HandlerError)` if payload is malformed or PID is unknown.
///
/// # Errors
///
/// Returns `HandlerError::PayloadTooShort` if data length is < 32 bytes, or `HandlerError::ProcessNotFound`.
pub fn handle_image_load(record: &EventRecord) -> Result<(), HandlerError> {
    const MIN_IMAGE_STRUCT_SIZE: usize = 32;

    if record.user_data.len() < MIN_IMAGE_STRUCT_SIZE {
        return Err(HandlerError::PayloadTooShort {
            expected: MIN_IMAGE_STRUCT_SIZE,
            actual: record.user_data.len(),
        });
    }

    let data = &record.user_data;

    let image_base = u64::from_ne_bytes(data[0..8].try_into().unwrap());
    let image_size = u64::from_ne_bytes(data[8..16].try_into().unwrap());
    let pid = u32::from_ne_bytes(data[16..20].try_into().unwrap());
    let checksum = u32::from_ne_bytes(data[20..24].try_into().unwrap());
    let default_base = u64::from_ne_bytes(data[24..32].try_into().unwrap());

    let (image_name, _) = extract_utf16_string(data, 32);

    let module = LoadedModule {
        base_address: image_base,
        image_size,
        image_name: image_name.unwrap_or_default(),
        load_time: record.timestamp,
        checksum,
        default_base,
    };

    if let Some(ctx) = TREE.get_by_pid(pid) {
        ctx.record_module_load(module);
    } else {
        return Err(HandlerError::ProcessNotFound(pid));
    }

    Ok(())
}

/// Handles module unmap events (`OPCODE_IMAGE_UNLOAD`).
///
/// # Arguments
///
/// * `record` - The raw ETW event record containing unmapped image address.
///
/// # Returns
///
/// `Ok(())` on success, or `Err(HandlerError)` if payload is malformed.
///
/// # Errors
///
/// Returns `HandlerError::PayloadTooShort` if user data length is < 20 bytes.
pub fn handle_image_unload(record: &EventRecord) -> Result<(), HandlerError> {
    const MIN_IMAGE_STRUCT_SIZE: usize = 20;

    if record.user_data.len() < MIN_IMAGE_STRUCT_SIZE {
        return Err(HandlerError::PayloadTooShort {
            expected: MIN_IMAGE_STRUCT_SIZE,
            actual: record.user_data.len(),
        });
    }

    let data = &record.user_data;
    let image_base = u64::from_ne_bytes(data[0..8].try_into().unwrap());
    let pid = u32::from_ne_bytes(data[16..20].try_into().unwrap());

    if let Some(ctx) = TREE.get_by_pid(pid) {
        ctx.record_module_unload(image_base);
    }

    Ok(())
}
