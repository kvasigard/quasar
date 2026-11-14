//! System Logger V2 and NT Kernel Logger ETW session implementation.
//!
//! By default, [`KernelSession`] uses modern Windows `EVENT_TRACE_SYSTEM_LOGGER_MODE` (`0x0200_0000`)
//! with `EVENT_TRACE_PROPERTIES_V2` and a 256-bit [`PerfGroupMask`] under a dedicated session name
//! (`"Pulsar-Kernel-Logger"`). This avoids OS-wide singleton collisions with tools like Process Monitor
//! or WPR and unlocks extended kernel groups (`PERF_VIRTUAL_ALLOC`, `PERF_OB_HANDLE`, etc.).

use std::ffi::c_void;
use std::mem::size_of;
use std::sync::atomic::{AtomicBool, Ordering};

use windows_sys::Win32::Foundation::ERROR_SUCCESS;
use windows_sys::Win32::System::Diagnostics::Etw::{
    CLASSIC_EVENT_ID, CONTROLTRACE_HANDLE, EVENT_TRACE_SYSTEM_LOGGER_MODE, SystemTraceControlGuid,
    TraceSetInformation, TraceStackTracingInfo, TraceSystemTraceEnableFlagsInfo,
};
use windows_sys::core::GUID;

use super::consumer::ConsumerHandle;
use super::error::EtwError;
pub use super::masks::{KernelFlag, PerfGroupMask};
use super::properties::TraceStatistics;
use super::router::TraceRouter;
use super::session::{
    EtwSession, EtwSessionBuilder, EventTraceProperties, flush_win32_trace_session,
    query_win32_trace_session, spawn_session_consumer, start_win32_trace_session,
    stop_win32_trace_session,
};

/// Process-local RAII guard ensuring only one kernel logger instance is active per Pulsar agent process.
pub struct NtKernelGuard(());

static IS_TAKEN: AtomicBool = AtomicBool::new(false);

impl NtKernelGuard {
    /// Attempts to acquire the process-local lock for the kernel logger.
    pub fn acquire() -> Result<Self, EtwError> {
        if IS_TAKEN
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            log::debug!(target: "etw_kernel", "Successfully acquired Kernel Logger lock.");
            Ok(Self(()))
        } else {
            log::warn!(target: "etw_kernel", "Failed to acquire Kernel Logger lock: Already in use.");
            Err(EtwError::KernelLoggerAlreadyActive)
        }
    }
}

impl Drop for NtKernelGuard {
    fn drop(&mut self) {
        IS_TAKEN.store(false, Ordering::SeqCst);
        log::debug!(target: "etw_kernel", "Released Kernel Logger lock via RAII guard.");
    }
}

/// Builder for configuring a [`KernelSession`] with a 256-bit [`PerfGroupMask`] and batch stack walk hooks.
pub struct KernelSessionBuilder {
    session_name: String,
    use_system_logger_v2: bool,
    properties: EventTraceProperties,
    group_mask: PerfGroupMask,
    stack_tracing_events: Vec<(GUID, u8)>,
}

impl Default for KernelSessionBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl KernelSessionBuilder {
    /// Creates a new `KernelSessionBuilder` targeting the modern `"Pulsar-Kernel-Logger"` V2 session.
    pub fn new() -> Self {
        Self {
            session_name: KernelSession::DEFAULT_SESSION_NAME.to_string(),
            use_system_logger_v2: true,
            properties: EventTraceProperties::default(),
            group_mask: PerfGroupMask::empty(),
            stack_tracing_events: Vec::new(),
        }
    }

    /// Overrides the kernel session name (defaults to `"Pulsar-Kernel-Logger"`).
    pub fn with_session_name(&mut self, name: impl Into<String>) -> &mut Self {
        self.session_name = name.into();
        self
    }

    /// Configures the builder to use the legacy `"NT Kernel Logger"` singleton instead of V2 System Logger mode.
    pub fn with_legacy_nt_kernel_logger(&mut self, legacy: bool) -> &mut Self {
        self.use_system_logger_v2 = !legacy;
        if legacy {
            self.session_name = KernelSession::LEGACY_SESSION_NAME.to_string();
        } else if self.session_name == KernelSession::LEGACY_SESSION_NAME {
            self.session_name = KernelSession::DEFAULT_SESSION_NAME.to_string();
        }
        self
    }

    /// Enables a specific [`KernelFlag`] in the 256-bit [`PerfGroupMask`].
    pub fn enable_flag(&mut self, flag: KernelFlag) -> &mut Self {
        log::trace!(target: "etw_kernel", "Enabling kernel flag: {:?}", flag);
        self.group_mask.insert(flag);
        self
    }

    /// Merges an entire [`PerfGroupMask`] into this builder.
    pub fn enable_group_mask(&mut self, mask: PerfGroupMask) -> &mut Self {
        self.group_mask |= mask;
        self
    }

    /// Instructs the kernel logger to capture call stack traces (`StackWalk_TypeGroup1`) for a specific `(GUID, Opcode)` pair.
    ///
    /// All registered events are submitted atomically in a single `TraceSetInformation(TraceStackTracingInfo)` call.
    pub fn enable_stack_tracing(&mut self, guid: GUID, event_type: u8) -> &mut Self {
        let exists = self.stack_tracing_events.iter().any(|(g, t)| {
            g.data1 == guid.data1
                && g.data2 == guid.data2
                && g.data3 == guid.data3
                && g.data4 == guid.data4
                && *t == event_type
        });

        if !exists {
            log::debug!(
                target: "etw_kernel",
                "Registering kernel stack tracing for event opcode: {}",
                event_type
            );
            self.stack_tracing_events.push((guid, event_type));
        }
        self
    }

    /// Returns a reference to the configured [`PerfGroupMask`].
    pub const fn group_mask(&self) -> &PerfGroupMask {
        &self.group_mask
    }

    /// Consumes the builder recipe to produce a configured [`KernelSession`].
    pub fn build(&self) -> Result<KernelSession, EtwError> {
        let guard = NtKernelGuard::acquire()?;

        let mut props = self.properties.clone();
        if self.use_system_logger_v2 {
            props.log_file_mode |= EVENT_TRACE_SYSTEM_LOGGER_MODE;
        }

        Ok(KernelSession {
            session_name: self.session_name.clone(),
            use_system_logger_v2: self.use_system_logger_v2,
            properties: props,
            group_mask: self.group_mask,
            stack_tracing_events: self.stack_tracing_events.clone(),
            handle: None,
            last_statistics: None,
            _guard: Some(guard),
        })
    }
}

impl EtwSessionBuilder for KernelSessionBuilder {
    fn set_buffer_size(&mut self, size: u32) -> &mut Self {
        self.properties.buffer_size = size;
        self
    }

    fn set_min_buffers(&mut self, count: u32) -> &mut Self {
        self.properties.minimum_buffers = count;
        self
    }

    fn set_max_buffers(&mut self, count: u32) -> &mut Self {
        self.properties.maximum_buffers = count;
        self
    }

    fn set_maximum_file_size(&mut self, size_mb: u32) -> &mut Self {
        self.properties.maximum_file_size = size_mb;
        self
    }

    fn set_log_file_mode(&mut self, mode: u32) -> &mut Self {
        self.properties.log_file_mode = mode;
        self
    }

    fn set_flush_timer(&mut self, seconds: u32) -> &mut Self {
        self.properties.flush_timer = seconds;
        self
    }

    fn set_log_file_name(&mut self, name: String) -> &mut Self {
        self.properties.log_file_name = Some(name);
        self
    }
}

/// Active or configured session object managing the lifecycle of a System Logger V2 or NT Kernel Logger session.
pub struct KernelSession {
    session_name: String,
    use_system_logger_v2: bool,
    properties: EventTraceProperties,
    group_mask: PerfGroupMask,
    stack_tracing_events: Vec<(GUID, u8)>,
    handle: Option<CONTROLTRACE_HANDLE>,
    last_statistics: Option<TraceStatistics>,
    _guard: Option<NtKernelGuard>,
}

impl KernelSession {
    /// Default modern System Logger V2 session name.
    pub const DEFAULT_SESSION_NAME: &'static str = "Pulsar-Kernel-Logger";

    /// Legacy singleton session name (`"NT Kernel Logger"`).
    pub const LEGACY_SESSION_NAME: &'static str = "NT Kernel Logger";

    /// Backwards-compatible constant alias.
    pub const SESSION_NAME: &'static str = Self::DEFAULT_SESSION_NAME;

    /// Returns the active session name.
    #[inline]
    pub fn session_name(&self) -> &str {
        &self.session_name
    }

    /// Returns the configured 256-bit [`PerfGroupMask`].
    #[inline]
    pub const fn group_mask(&self) -> &PerfGroupMask {
        &self.group_mask
    }

    /// Returns the legacy 32-bit `EnableFlags` bitmask projection.
    #[inline]
    pub const fn get_enable_flags_mask(&self) -> u32 {
        self.group_mask.legacy_enable_flags()
    }

    /// Returns the [`TraceStatistics`] captured when the session was last queried or stopped.
    #[inline]
    pub const fn last_statistics(&self) -> Option<TraceStatistics> {
        self.last_statistics
    }

    /// Queries live kernel ring-buffer statistics for this session.
    pub fn query_statistics(&self) -> Result<TraceStatistics, EtwError> {
        let handle = self
            .handle
            .ok_or_else(|| EtwError::SessionNotStarted(self.session_name.clone()))?;
        query_win32_trace_session(handle, &self.session_name, &self.properties, self.session_guid())
    }

    /// Flushes active kernel ring buffers immediately.
    pub fn flush(&self) -> Result<TraceStatistics, EtwError> {
        let handle = self
            .handle
            .ok_or_else(|| EtwError::SessionNotStarted(self.session_name.clone()))?;
        flush_win32_trace_session(handle, &self.session_name, &self.properties, self.session_guid())
    }

    #[inline]
    const fn session_guid(&self) -> GUID {
        if self.use_system_logger_v2 {
            GUID {
                data1: 0,
                data2: 0,
                data3: 0,
                data4: [0; 8],
            }
        } else {
            SystemTraceControlGuid
        }
    }

    /// Builds the contiguous `[CLASSIC_EVENT_ID]` array for batch submission to `TraceSetInformation`.
    pub(crate) fn build_classic_event_ids(&self) -> Vec<CLASSIC_EVENT_ID> {
        self.stack_tracing_events
            .iter()
            .map(|(guid, event_type)| CLASSIC_EVENT_ID {
                EventGuid: *guid,
                Type: *event_type,
                Reserved: [0; 7],
            })
            .collect()
    }

    /// Applies the 256-bit [`PerfGroupMask`] (`TraceSystemTraceEnableFlagsInfo`) and the contiguous
    /// `[CLASSIC_EVENT_ID]` stack-walk hook list (`TraceStackTracingInfo`) to the started session.
    fn configure_kernel_extensions(&self, handle: CONTROLTRACE_HANDLE) {
        // 1. Apply full 8-slot PerfGroupMask via TraceSetInformation(TraceSystemTraceEnableFlagsInfo)
        if self.use_system_logger_v2 || self.group_mask.has_extended_flags() {
            // SAFETY: `self.group_mask` is `#[repr(C)]` with `[u32; 8]` (32 bytes), matching `PERFINFO_GROUPMASK`.
            let status = unsafe {
                TraceSetInformation(
                    handle,
                    TraceSystemTraceEnableFlagsInfo,
                    &self.group_mask as *const PerfGroupMask as *const c_void,
                    size_of::<PerfGroupMask>() as u32,
                )
            };
            if status != ERROR_SUCCESS {
                log::warn!(
                    target: "etw_kernel",
                    "TraceSetInformation(TraceSystemTraceEnableFlagsInfo) returned Win32 code {}",
                    status
                );
            }
        }

        // 2. Apply all registered stack-walk hooks in a SINGLE TraceSetInformation call
        // (calling TraceStackTracingInfo in a loop would overwrite previous hooks!).
        let hook_ids = self.build_classic_event_ids();
        if !hook_ids.is_empty() {
            let byte_size = (hook_ids.len() * size_of::<CLASSIC_EVENT_ID>()) as u32;
            // SAFETY: `hook_ids` is a contiguous slice of `CLASSIC_EVENT_ID` structs of `byte_size` bytes.
            let status = unsafe {
                TraceSetInformation(
                    handle,
                    TraceStackTracingInfo,
                    hook_ids.as_ptr() as *const c_void,
                    byte_size,
                )
            };

            if status != ERROR_SUCCESS {
                log::warn!(
                    target: "etw_kernel",
                    "Failed to enable batch kernel stack tracing for {} event types (Win32 code: {})",
                    hook_ids.len(),
                    status
                );
            } else {
                log::debug!(
                    target: "etw_kernel",
                    "Batch kernel stack tracing enabled for {} event types.",
                    hook_ids.len()
                );
            }
        }
    }
}

impl EtwSession for KernelSession {
    fn start(&mut self) -> Result<(), EtwError> {
        if self.handle.is_some() {
            log::warn!(
                target: "etw_kernel",
                "Attempted to start an already running KernelSession ('{}').",
                self.session_name
            );
            return Err(EtwError::SessionAlreadyRunning(self.session_name.clone()));
        }

        log::info!(
            target: "etw_kernel",
            "Starting kernel ETW session '{}' (SystemLoggerV2={})...",
            self.session_name,
            self.use_system_logger_v2
        );

        let result = start_win32_trace_session(
            &self.session_name,
            &self.properties,
            self.session_guid(),
            Some(&self.group_mask),
            self.use_system_logger_v2,
        );

        let handle = match result {
            Ok(h) => h,
            Err(err) if self.use_system_logger_v2 => {
                log::warn!(
                    target: "etw_kernel",
                    "System Logger V2 startup failed ({}); falling back to legacy '{}'",
                    err,
                    Self::LEGACY_SESSION_NAME
                );
                self.use_system_logger_v2 = false;
                self.session_name = Self::LEGACY_SESSION_NAME.to_string();
                self.properties.log_file_mode &= !EVENT_TRACE_SYSTEM_LOGGER_MODE;
                start_win32_trace_session(
                    &self.session_name,
                    &self.properties,
                    SystemTraceControlGuid,
                    Some(&self.group_mask),
                    false,
                )?
            }
            Err(err) => return Err(err),
        };

        self.handle = Some(handle);
        self.configure_kernel_extensions(handle);
        log::debug!(
            target: "etw_kernel",
            "Successfully started kernel ETW session '{}'.",
            self.session_name
        );
        Ok(())
    }

    fn stop(&mut self) -> Result<(), EtwError> {
        let Some(handle) = self.handle.take() else {
            self._guard = None;
            return Ok(());
        };

        log::info!(
            target: "etw_kernel",
            "Stopping kernel ETW session '{}'...",
            self.session_name
        );

        let stats_res = stop_win32_trace_session(
            handle,
            &self.session_name,
            &self.properties,
            self.session_guid(),
        );
        self._guard = None;

        let stats = stats_res?;
        self.last_statistics = Some(stats);
        log::debug!(
            target: "etw_kernel",
            "Kernel ETW session '{}' stopped (buffers_written={}, events_lost={}).",
            self.session_name,
            stats.buffers_written,
            stats.events_lost
        );
        Ok(())
    }

    fn consume_with_router<R: TraceRouter>(&self, router: R) -> Result<ConsumerHandle, EtwError> {
        spawn_session_consumer(self.handle.is_some(), &self.session_name, router)
    }
}

impl Drop for KernelSession {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kernel_builder_batch_stack_trace_and_group_mask() {
        let guid_a = GUID {
            data1: 0xce1dbfb4,
            data2: 0x137e,
            data3: 0x4da6,
            data4: [0x87, 0xb0, 0x3f, 0x59, 0xaa, 0x10, 0x2c, 0xbc],
        };
        let guid_b = GUID {
            data1: 0x3d6fa8d0,
            data2: 0xfe05,
            data3: 0x11d0,
            data4: [0x9d, 0xda, 0x00, 0xc0, 0x4f, 0xd7, 0xba, 0x7c],
        };

        let mut builder = KernelSessionBuilder::new();
        builder
            .enable_flag(KernelFlag::Process)
            .enable_flag(KernelFlag::ImageLoad)
            .enable_flag(KernelFlag::VirtualAlloc)
            .enable_stack_tracing(guid_a, 51)
            .enable_stack_tracing(guid_b, 1)
            .enable_stack_tracing(guid_a, 51); // Duplicate should be ignored

        let session = builder.build().expect("KernelSession build should succeed");
        assert_eq!(session.session_name(), "Pulsar-Kernel-Logger");
        assert!(session.group_mask().contains(KernelFlag::Process));
        assert!(session.group_mask().contains(KernelFlag::ImageLoad));
        assert!(session.group_mask().contains(KernelFlag::VirtualAlloc));

        let hooks = session.build_classic_event_ids();
        assert_eq!(hooks.len(), 2, "Batch stack trace hooks must retain both events without overwriting");
        assert_eq!(hooks[0].Type, 51);
        assert_eq!(hooks[1].Type, 1);
    }
}
