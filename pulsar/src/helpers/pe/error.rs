//! Structured error taxonomy for Portable Executable (PE) parsing.

use thiserror::Error;

/// Structured error conditions encountered when decoding Portable Executable (PE) headers.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PeError {
    /// Binary buffer is shorter than the minimum expected structure size.
    #[error("PE buffer too small: expected at least {expected} bytes, got {actual}")]
    BufferTooSmall {
        /// Expected minimum byte length.
        expected: usize,
        /// Actual available byte length.
        actual: usize,
    },
    /// The file does not start with the mandatory DOS magic (`0x5A4D` / `"MZ"`).
    #[error("Invalid DOS header signature (missing MZ)")]
    InvalidDosSignature,
    /// `e_lfanew` points outside the valid bounds of the file buffer.
    #[error("Invalid PE header offset (e_lfanew: {0:#x})")]
    InvalidPeHeaderOffset(usize),
    /// The NT signature is not `0x00004550` (`"PE\0\0"`).
    #[error("Invalid NT PE signature (missing PE\\0\\0)")]
    InvalidPeSignature,
    /// Optional header magic is unrecognized (neither PE32 `0x010B` nor PE32+ `0x020B`).
    #[error("Unsupported optional header magic: {0:#x}")]
    UnsupportedOptionalHeaderMagic(u16),
    /// Section header table is out of bounds or truncated.
    #[error("Section headers are truncated or out of bounds")]
    TruncatedSectionHeaders,
    /// Export table RVA does not map to any valid section within the file.
    #[error("Export directory RVA {0:#x} does not fall within any PE section")]
    ExportTableRvaOutOfBounds(u32),
    /// An exported name or string pointer is malformed or out of bounds.
    #[error("Exported function name or DLL name string pointer is invalid")]
    InvalidExportStringPointer,
    /// I/O error occurred while reading from the filesystem.
    #[error("PE file I/O error: {0}")]
    IoError(String),
}
