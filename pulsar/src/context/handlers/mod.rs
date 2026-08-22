//! Domain-partitioned telemetry ingestion handlers and binary deserializers.

pub mod file;
pub mod image;
pub mod process;

pub use file::{
    handle_file_create, handle_file_name, handle_file_operation, handle_file_read_write,
    handle_file_write,
};
pub use image::{handle_image_load, handle_image_unload};
pub use process::{handle_process_exit, handle_process_start};
