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
    let default_base = u64::from_ne_bytes(data[24..32].try_into().unwrap());

    let (image_name, _) = extract_utf16_string(data, 32);
    let resolved_name = image_name.unwrap_or_default();

    let file_key = if !resolved_name.is_empty() {
        Some(
            CONTEXT
                .get_or_create_file(&resolved_name, record.timestamp)
                .key,
        )
    } else {
        None
    };

    let module = LoadedModule::new(
        image_base,
        image_size,
        resolved_name,
        file_key,
        record.timestamp,
        checksum,
        default_base,
        false,
    );

    let process_key = if let Some(ctx) = CONTEXT.get_process(pid) {
        ctx.record_module_load(module.clone());
        ctx.key
    } else {
        return Err(HandlerError::ProcessNotFound(pid));
    };

    Ok(ImageLoadEvent {
        process_key,
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
