//! Zero-copy binary DTO schemas and cursor primitives for Windows ETW payloads.

pub mod cursor;
pub mod nt_kernel;

pub use cursor::{ByteCursor, CursorError};
