//! Filesystem file I/O telemetry ingestion handlers.

use crate::context::CONTEXT;
use crate::context::identity::ProcessKey;
use crate::context::models::file::{FileAccessRecord, FileOperationKind};
use crate::error::HandlerError;
use crate::helpers::strings::*;
use crate::pipeline::event::{FileCreateEvent, FileOperationEvent, FileReadWriteEvent};
use crate::sensors::etw::EventRecord;

/// Handles and idempotently ingests file creation and file open events.
///
/// # Arguments
///
/// * `record` - The incoming ETW event record containing FileIo_Create payload.
///
/// # Returns
///
/// A [`FileCreateEvent`] describing the created or opened file.
///
/// # Errors
///
/// Returns [`HandlerError::PayloadTooShort`] if the user data buffer is smaller than the minimum struct size.
#[tracing::instrument(name = "handle_file_create", skip(record), level = "debug")]
pub fn handle_file_create(record: &EventRecord) -> Result<FileCreateEvent, HandlerError> {
    const MIN_CREATE_STRUCT_SIZE: usize = 36;

    if record.user_data.len() < MIN_CREATE_STRUCT_SIZE {
        return Err(HandlerError::PayloadTooShort {
            expected: MIN_CREATE_STRUCT_SIZE,
            actual: record.user_data.len(),
        });
    }

    let data = &record.user_data;

    // FileIo_Create 64-bit layout
    let file_object = u64::from_ne_bytes(data[16..24].try_into().unwrap());
    let create_options = u32::from_ne_bytes(data[24..28].try_into().unwrap());
    let file_attributes = u32::from_ne_bytes(data[28..32].try_into().unwrap());
    let share_access = u32::from_ne_bytes(data[32..36].try_into().unwrap());

    let (open_path, _) = extract_utf16_string(data, 36);
    let resolved_path = open_path.unwrap_or_default();

    let file_ctx = CONTEXT.get_or_create_file(&resolved_path, record.timestamp);
    let file_key = file_ctx.key;

    if file_object != 0 {
        CONTEXT.files.map_file_object(file_object, file_key);
    }

    // Record creation in access history
    file_ctx.record_access(FileAccessRecord {
        operation: FileOperationKind::Create,
        timestamp: record.timestamp,
        bytes_transferred: 0,
        is_write: true,
    });

    let process_key = if let Some(proc) = CONTEXT.get_process(record.process_id) {
        proc.record_file_access(file_key);
        proc.key
    } else {
        ProcessKey::from_raw(0)
    };

    Ok(FileCreateEvent {
        process_key,
        pid: record.process_id,
        file_key,
        file_object,
        file_path: file_ctx.path.clone(),
        create_options,
        file_attributes,
        share_access,
        timestamp: record.timestamp,
    })
}

/// Handles file name resolution and file rundown events (FileIo_Name).
///
/// # Arguments
///
/// * `record` - The incoming ETW event record containing FileIo_Name payload.
///
/// # Returns
///
/// An optional [`FileCreateEvent`] describing the registered file entity.
///
/// # Errors
///
/// Returns [`HandlerError::PayloadTooShort`] if the user data buffer is smaller than the minimum struct size.
#[tracing::instrument(name = "handle_file_name", skip(record), level = "debug")]
pub fn handle_file_name(record: &EventRecord) -> Result<Option<FileCreateEvent>, HandlerError> {
    const MIN_NAME_STRUCT_SIZE: usize = 8;

    if record.user_data.len() < MIN_NAME_STRUCT_SIZE {
        return Err(HandlerError::PayloadTooShort {
            expected: MIN_NAME_STRUCT_SIZE,
            actual: record.user_data.len(),
        });
    }

    let data = &record.user_data;
    let file_object = u64::from_ne_bytes(data[0..8].try_into().unwrap());

    let (file_name, _) = extract_utf16_string(data, 8);
    let Some(resolved_path) = file_name else {
        return Ok(None);
    };

    if resolved_path.is_empty() {
        return Ok(None);
    }

    let file_ctx = CONTEXT.get_or_create_file(&resolved_path, record.timestamp);
    let file_key = file_ctx.key;

    if file_object != 0 {
        CONTEXT.files.map_file_object(file_object, file_key);
    }

    let process_key = if let Some(proc) = CONTEXT.get_process(record.process_id) {
        proc.record_file_access(file_key);
        proc.key
    } else {
        ProcessKey::from_raw(0)
    };

    Ok(Some(FileCreateEvent {
        process_key,
        pid: record.process_id,
        file_key,
        file_object,
        file_path: file_ctx.path.clone(),
        create_options: 0,
        file_attributes: 0,
        share_access: 0,
        timestamp: record.timestamp,
    }))
}

/// Handles file read and write operations.
///
/// # Arguments
///
/// * `record` - The incoming ETW event record containing FileIo_ReadWrite payload.
/// * `is_write` - Whether the operation is a write (`true`) or read (`false`).
///
/// # Returns
///
/// A [`FileReadWriteEvent`] describing the read or write activity.
///
/// # Errors
///
/// Returns [`HandlerError::PayloadTooShort`] if the user data buffer is smaller than the minimum struct size.
#[tracing::instrument(name = "handle_file_read_write", skip(record), level = "debug")]
pub fn handle_file_read_write(
    record: &EventRecord,
    is_write: bool,
) -> Result<FileReadWriteEvent, HandlerError> {
    const MIN_READWRITE_STRUCT_SIZE: usize = 48;

    if record.user_data.len() < MIN_READWRITE_STRUCT_SIZE {
        return Err(HandlerError::PayloadTooShort {
            expected: MIN_READWRITE_STRUCT_SIZE,
            actual: record.user_data.len(),
        });
    }

    let data = &record.user_data;

    let offset = u64::from_ne_bytes(data[0..8].try_into().unwrap());
    let file_object = u64::from_ne_bytes(data[24..32].try_into().unwrap());
    let io_size = u32::from_ne_bytes(data[40..44].try_into().unwrap());
    let io_flags = u32::from_ne_bytes(data[44..48].try_into().unwrap());

    // Resolve file key and path via FileObject map
    let file_key = CONTEXT.files.get_key_by_file_object(file_object);
    let mut file_path = None;

    if let Some(key) = file_key
        && let Some(file_ctx) = CONTEXT.files.get_by_key(key)
    {
        file_path = Some(file_ctx.path.clone());
        file_ctx.record_access(FileAccessRecord {
            operation: if is_write {
                FileOperationKind::Write
            } else {
                FileOperationKind::Read
            },
            timestamp: record.timestamp,
            bytes_transferred: io_size as u64,
            is_write,
        });
    }

    let process_key = if let Some(proc) = CONTEXT.get_process(record.process_id) {
        if let Some(key) = file_key {
            proc.record_file_access(key);
        }
        proc.key
    } else {
        ProcessKey::from_raw(0)
    };

    Ok(FileReadWriteEvent {
        process_key,
        pid: record.process_id,
        file_key,
        file_object,
        file_path,
        is_write,
        offset,
        io_size,
        io_flags,
        timestamp: record.timestamp,
    })
}

/// Convenience alias for handling file write events.
///
/// # Arguments
///
/// * `record` - The incoming ETW event record containing FileIo_ReadWrite payload.
///
/// # Returns
///
/// A [`FileReadWriteEvent`] configured with `is_write = true`.
#[inline]
pub fn handle_file_write(record: &EventRecord) -> Result<FileReadWriteEvent, HandlerError> {
    handle_file_read_write(record, true)
}

/// Handles file lifecycle and metadata operations (SetInfo, Delete, Rename, Close, Cleanup, Flush).
///
/// # Arguments
///
/// * `record` - The incoming ETW event record.
///
/// # Returns
///
/// A [`FileOperationEvent`] describing the operation.
///
/// # Errors
///
/// Returns [`HandlerError::PayloadTooShort`] if the user data buffer is smaller than the minimum struct size.
#[tracing::instrument(name = "handle_file_operation", skip(record), level = "debug")]
pub fn handle_file_operation(record: &EventRecord) -> Result<FileOperationEvent, HandlerError> {
    const MIN_SIMPLEOP_STRUCT_SIZE: usize = 24;

    if record.user_data.len() < MIN_SIMPLEOP_STRUCT_SIZE {
        return Err(HandlerError::PayloadTooShort {
            expected: MIN_SIMPLEOP_STRUCT_SIZE,
            actual: record.user_data.len(),
        });
    }

    let data = &record.user_data;
    let file_object = u64::from_ne_bytes(data[16..24].try_into().unwrap());

    let (extra_info, info_class) = if data.len() >= 44 {
        let extra = u64::from_ne_bytes(data[32..40].try_into().unwrap());
        let info = u32::from_ne_bytes(data[40..44].try_into().unwrap());
        (extra, info)
    } else {
        (0, 0)
    };

    let operation = match record.opcode {
        65 => FileOperationKind::Cleanup,
        66 => FileOperationKind::Close,
        69 => FileOperationKind::SetInformation,
        70 => FileOperationKind::Delete,
        71 => FileOperationKind::Rename,
        73 => FileOperationKind::Flush,
        _ => FileOperationKind::Open,
    };

    // Unmap FileObject on Close to prevent unbounded memory growth
    let file_key = if operation == FileOperationKind::Close {
        CONTEXT.files.unmap_file_object(file_object)
    } else {
        CONTEXT.files.get_key_by_file_object(file_object)
    };

    let mut file_path = None;
    if let Some(key) = file_key
        && let Some(file_ctx) = CONTEXT.files.get_by_key(key)
    {
        file_path = Some(file_ctx.path.clone());
        let is_write = matches!(
            operation,
            FileOperationKind::SetInformation
                | FileOperationKind::Delete
                | FileOperationKind::Rename
        );
        file_ctx.record_access(FileAccessRecord {
            operation,
            timestamp: record.timestamp,
            bytes_transferred: 0,
            is_write,
        });
    }

    let process_key = if let Some(proc) = CONTEXT.get_process(record.process_id) {
        if let Some(key) = file_key {
            proc.record_file_access(key);
        }
        proc.key
    } else {
        ProcessKey::from_raw(0)
    };

    Ok(FileOperationEvent {
        process_key,
        pid: record.process_id,
        file_key,
        file_object,
        file_path,
        operation,
        extra_info,
        info_class,
        timestamp: record.timestamp,
    })
}
