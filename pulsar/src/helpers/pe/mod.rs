//! Pure-Rust Portable Executable (PE) header parser and export directory extraction.

pub mod error;
pub mod models;
pub mod parser;

#[cfg(test)]
mod tests;

pub use error::PeError;
pub use models::{
    PeExport, PeExportDirectory, PeInfo, PeSection, file_flags, machine, magic, section_flags,
};
pub use parser::PeParser;
