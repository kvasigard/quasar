//! Zero-copy binary DTO schemas and bitness-aware cursor primitives for Windows ETW payloads.
//!
//! # Architecture & Why We Avoid Runtime TDH (`TdhGetEventInformation`)
//!
//! Windows provides the Trace Data Helper (`tdh.dll`) API to dynamically look up ETW manifest
//! and MOF schemas at runtime, and some general-purpose ETW crates rely on it (or build a custom
//! schema locator cache). For an EDR agent processing high-frequency kernel telemetry, runtime
//! schema lookups introduce significant overhead, string-keyed map lookups, and failure modes
//! when MOF/WMI metadata is missing or tampered with.
//!
//! Instead, this module combines:
//! 1. **[`ByteCursor`]:** A zero-cost, sequential binary reader parameterized by the event's
//!    actual pointer byte width (`4` bytes for 32-bit WOW64 events vs. `8` bytes for 64-bit
//!    events, derived from `EVENT_HEADER_FLAG_32_BIT_HEADER`).
//! 2. **Compile-Time Versioned DTOs ([`nt_kernel`]):** Borrowed zero-copy structs (`'a`) for each
//!    documented Windows MOF schema version (`Process_V0..V4`, `SysCallEnter`, `StackWalk`) that
//!    slice directly into [`RawEvent::user_data`](crate::sensors::etw::RawEvent::user_data) without
//!    heap allocation.

pub mod cursor;
pub mod nt_kernel;

pub use cursor::{ByteCursor, CursorError};
