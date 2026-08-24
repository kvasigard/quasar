//! Dynamic library and executable image mapping handlers.

use crate::context::CONTEXT;
use crate::context::identity::ProcessKey;
use crate::context::models::module::LoadedModule;
use crate::error::HandlerError;
use crate::helpers::strings::*;
use crate::pipeline::event::{ImageLoadEvent, ImageUnloadEvent};
use crate::sensors::etw::EventRecord;

/// Handles and idempotently ingests module mapping events.
///
/// If the DLL at `base_address` is already tracked in this process (e.g. from repeat rundowns),
/// updates metadata in-place without creating duplicate records.
///
/// # Arguments
///
/// * `record` - The incoming ETW event record containing image load payload.
///
/// # Returns
///
/// An [`ImageLoadEvent`] describing the loaded module.
///
/// # Errors
///
/// Returns [`HandlerError::PayloadTooShort`] if data is truncated, or [`HandlerError::ProcessNotFound`] if the process PID is unknown.
#[tracing::instrument(name = "handle_image_load", skip(record), level = "debug")]
pub fn handle_image_load(record: &EventRecord) -> Result<ImageLoadEvent, HandlerError> {
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
    let default_base = if data.len() >= 40 {
        u64::from_ne_bytes(data[32..40].try_into().unwrap())
    } else {
        u64::from_ne_bytes(data[24..32].try_into().unwrap())
    };

    let resolved_name = extract_image_path(data);

    let file_key = if !resolved_name.is_empty() {
        Some(
            CONTEXT
                .get_or_create_file(&resolved_name, record.timestamp)
                .key,
        )
    } else {
        None
    };

    let info = CONTEXT.get_or_create_module_info(
        file_key,
        &resolved_name,
        image_size,
        checksum,
        default_base,
    );

    let is_unbacked = file_key.is_none();
    let module = LoadedModule::with_info(image_base, record.timestamp, is_unbacked, info);

    if module.is_system() {
        CONTEXT.record_system_module(module.clone());
    }

    let proc_ctx = CONTEXT.get_or_create_process(pid, record.timestamp);
    proc_ctx.record_module_load(module.clone());

    Ok(ImageLoadEvent {
        process_key: proc_ctx.key,
        pid,
        module,
        timestamp: record.timestamp,
    })
}

/// Handles module unmap events idempotently.
///
/// # Arguments
///
/// * `record` - The incoming ETW event record containing image unload payload.
///
/// # Returns
///
/// An [`ImageUnloadEvent`] describing the unmapped module.
///
/// # Errors
///
/// Returns [`HandlerError::PayloadTooShort`] if data is truncated.
#[tracing::instrument(name = "handle_image_unload", skip(record), level = "debug")]
pub fn handle_image_unload(record: &EventRecord) -> Result<ImageUnloadEvent, HandlerError> {
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

    let process_key = if let Some(ctx) = CONTEXT.get_process(pid) {
        ctx.record_module_unload(image_base);
        ctx.key
    } else {
        ProcessKey::from_raw(0)
    };

    Ok(ImageUnloadEvent {
        process_key,
        pid,
        base_address: image_base,
        timestamp: record.timestamp,
    })
}

/// Robustly extracts the UTF-16 image file path from an ETW ImageLoad record.
///
/// In 64-bit Windows ETW NT Kernel Logger sessions, the MOF `Image_Load` header is 56 bytes,
/// and `FileName` starts at offset 56. In 32-bit or legacy sessions, it may start at 44, 48, 64, or 32.
/// This helper tries standard offsets first and falls back to a structural prefix scan.
fn extract_image_path(data: &[u8]) -> String {
    for &offset in &[56, 64, 48, 44, 32, 20] {
        if offset < data.len()
            && let (Some(path), _) = extract_utf16_string(data, offset)
        {
            let trimmed = path.trim();
            if !trimmed.is_empty() && (trimmed.contains('\\') || trimmed.contains('.')) {
                return trimmed.to_string();
            }
        }
    }

    // Defensive scan: look for common drive or device UTF-16 prefixes (e.g. '\', 'C', 'c')
    for offset in (20..data.len().saturating_sub(4)).step_by(2) {
        if (data[offset] == b'\\' || data[offset].is_ascii_alphabetic())
            && data[offset + 1] == 0
            && let (Some(path), _) = extract_utf16_string(data, offset)
        {
            let trimmed = path.trim();
            if trimmed.contains('\\') && trimmed.len() >= 3 {
                return trimmed.to_string();
            }
        }
    }

    String::new()
}
