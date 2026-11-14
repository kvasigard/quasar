//! Session director providing declarative profiles and modular recipes for ETW kernel and user sessions.
//!
//! # Role in the Architecture
//!
//! [`SessionDirector`] separates *what* telemetry an EDR deployment wants to collect
//! ([`KernelTraceConfig`] and [`Provider`] lists) from *how* [`KernelSessionBuilder`] and
//! [`UserSessionBuilder`] wire up underlying Win32 flags, buffer pools, and stack-walk hooks.
//!
//! By design, [`KernelTraceConfig::default()`] enables process and image-load context telemetry
//! (`PERF_PROCESS | PERF_IMAGE_LOAD`) while keeping extreme-volume system call tracing
//! (`PERF_SYSCALL` + `SysCallEnter` stack walking) **disabled (`false`) by default** unless
//! explicitly opted into via `--enable-syscalls` or [`KernelTraceConfig::with_syscalls`].

use windows_sys::Win32::System::Diagnostics::Etw::{
    EVENT_TRACE_REAL_TIME_MODE, PROCESS_TRACE_MODE_EVENT_RECORD, PROCESS_TRACE_MODE_RAW_TIMESTAMP,
};
use windows_sys::core::GUID;

use super::kernel::{KernelFlag, KernelSessionBuilder};
use super::provider::Provider;
use super::session::EtwSessionBuilder;
use super::user::UserSessionBuilder;

/// Classic MOF GUID for `PerfInfo` kernel events (`{ce1dbfb4-137e-4da6-87b0-3f59aa102cbc}`).
///
/// Used when registering `SysCallEnter` (Opcode 51) for kernel stack-walk capture via
/// `TraceSetInformation(TraceStackTracingInfo)`.
///
/// Reference: <https://learn.microsoft.com/en-us/windows/win32/etw/nt-kernel-logger-constants>
pub const PERFINFO_GUID: GUID = GUID {
    data1: 0xce1dbfb4,
    data2: 0x137e,
    data3: 0x4da6,
    data4: [0x87, 0xb0, 0x3f, 0x59, 0xaa, 0x10, 0x2c, 0xbc],
};

/// Classic MOF Opcode (`51`) for System Call Entry (`SysCallEnter`) under [`PERFINFO_GUID`].
pub const EVENT_ID_SYSCALL_ENTER: u8 = 51;

/// Default size of each ETW ring buffer in kilobytes (`1024` KB = `1` MB per buffer).
pub const DEFAULT_BUFFER_SIZE_KB: u32 = 1024;
/// Default minimum number of pre-allocated buffers in the ETW session pool (`64` MB minimum pool).
pub const DEFAULT_MIN_BUFFERS: u32 = 64;
/// Default maximum number of buffers in the ETW session pool (`128` MB maximum pool).
pub const DEFAULT_MAX_BUFFERS: u32 = 128;
/// Default forced buffer flush interval in seconds (`1` second).
pub const DEFAULT_FLUSH_TIMER_SECS: u32 = 1;

/// Declarative telemetry profile for configuring a System Logger V2 [`KernelSession`](super::kernel::KernelSession).
///
/// # Default Invariant
///
/// [`KernelTraceConfig::default()`] enables `enable_process` and `enable_image_load` so the
/// agent maintains an accurate process/module tree (`SystemState`), while leaving
/// `enable_syscalls` set to `false` by default because `PERF_SYSCALL` generates hundreds of
/// thousands of events per second across the OS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KernelTraceConfig {
    /// Enable process creation, termination, and rundown telemetry (`PERF_PROCESS`).
    pub enable_process: bool,
    /// Enable executable and DLL image load/unload telemetry (`PERF_IMAGE_LOAD`).
    pub enable_image_load: bool,
    /// Enable thread creation, termination, and rundown telemetry (`PERF_THREAD`).
    pub enable_threads: bool,
    /// Enable virtual memory allocation/free telemetry (`PERF_VIRTUAL_ALLOC`, `Masks[2]`).
    pub enable_virtual_alloc: bool,
    /// Enable Object Manager handle operation telemetry (`PERF_OB_HANDLE`, `Masks[4]`).
    pub enable_ob_handle: bool,
    /// Enable kernel system call (`SysCallEnter`) and stack walk telemetry (`PERF_SYSCALL`, `Masks[1]`).
    ///
    /// **Disabled (`false`) by default** due to extreme system-wide event volume.
    pub enable_syscalls: bool,
}

impl Default for KernelTraceConfig {
    fn default() -> Self {
        Self {
            enable_process: true,
            enable_image_load: true,
            enable_threads: false,
            enable_virtual_alloc: false,
            enable_ob_handle: false,
            enable_syscalls: false,
        }
    }
}

impl KernelTraceConfig {
    /// Creates the default EDR kernel trace profile (`Process` + `ImageLoad` enabled, `Syscalls` disabled).
    #[inline]
    pub const fn new() -> Self {
        Self {
            enable_process: true,
            enable_image_load: true,
            enable_threads: false,
            enable_virtual_alloc: false,
            enable_ob_handle: false,
            enable_syscalls: false,
        }
    }

    /// Toggles system call (`PERF_SYSCALL`) and `SysCallEnter` stack walk tracing.
    #[inline]
    pub const fn with_syscalls(mut self, enabled: bool) -> Self {
        self.enable_syscalls = enabled;
        self
    }

    /// Toggles both process (`PERF_PROCESS`) and image-load (`PERF_IMAGE_LOAD`) context tracing.
    #[inline]
    pub const fn with_context(mut self, enabled: bool) -> Self {
        self.enable_process = enabled;
        self.enable_image_load = enabled;
        self
    }

    /// Toggles thread lifecycle (`PERF_THREAD`) tracing.
    #[inline]
    pub const fn with_threads(mut self, enabled: bool) -> Self {
        self.enable_threads = enabled;
        self
    }

    /// Toggles virtual memory allocation (`PERF_VIRTUAL_ALLOC`) tracing.
    #[inline]
    pub const fn with_virtual_alloc(mut self, enabled: bool) -> Self {
        self.enable_virtual_alloc = enabled;
        self
    }

    /// Toggles Object Manager handle (`PERF_OB_HANDLE`) tracing.
    #[inline]
    pub const fn with_ob_handle(mut self, enabled: bool) -> Self {
        self.enable_ob_handle = enabled;
        self
    }
}

/// Stateless director providing composable configuration recipes for [`KernelSessionBuilder`]
/// and [`UserSessionBuilder`].
pub struct SessionDirector;

impl SessionDirector {
    /// Applies standard real-time logging modes and ring-buffer sizing polymorphically to any
    /// builder implementing [`EtwSessionBuilder`].
    pub fn configure_base_session(
        builder: &mut impl EtwSessionBuilder,
        buffer_size_kb: u32,
        min_buffers: u32,
        max_buffers: u32,
        flush_timer_secs: u32,
    ) {
        builder
            .set_log_file_mode(
                EVENT_TRACE_REAL_TIME_MODE
                    | PROCESS_TRACE_MODE_EVENT_RECORD
                    | PROCESS_TRACE_MODE_RAW_TIMESTAMP,
            )
            .set_buffer_size(buffer_size_kb)
            .set_min_buffers(min_buffers)
            .set_max_buffers(max_buffers)
            .set_flush_timer(flush_timer_secs);
    }

    /// Enables kernel system call emission (`KernelFlag::SystemCall`) and registers `SysCallEnter`
    /// (`PERFINFO_GUID`, Opcode 51) for out-of-band kernel stack walking.
    pub fn enable_syscall_monitoring(builder: &mut KernelSessionBuilder) {
        builder
            .enable_flag(KernelFlag::SystemCall)
            .enable_stack_tracing(PERFINFO_GUID, EVENT_ID_SYSCALL_ENTER);
    }

    /// Enables process creation, termination, and rundown telemetry (`KernelFlag::Process`).
    pub fn enable_process_monitoring(builder: &mut KernelSessionBuilder) {
        builder.enable_flag(KernelFlag::Process);
    }

    /// Enables executable and DLL image mapping/unmapping telemetry (`KernelFlag::ImageLoad`).
    pub fn enable_image_monitoring(builder: &mut KernelSessionBuilder) {
        builder.enable_flag(KernelFlag::ImageLoad);
    }

    /// Enables thread creation, termination, and rundown telemetry (`KernelFlag::Thread`).
    pub fn enable_thread_monitoring(builder: &mut KernelSessionBuilder) {
        builder.enable_flag(KernelFlag::Thread);
    }

    /// Configures a [`KernelSessionBuilder`] using [`KernelTraceConfig::default()`]
    /// (`Process` + `ImageLoad` enabled, `Syscalls` disabled by default).
    pub fn construct_default_kernel_session(builder: &mut KernelSessionBuilder) {
        Self::construct_kernel_session_with_config(builder, KernelTraceConfig::default());
    }

    /// Composes a tailored EDR kernel trace session from a declarative [`KernelTraceConfig`].
    pub fn construct_kernel_session_with_config(
        builder: &mut KernelSessionBuilder,
        config: KernelTraceConfig,
    ) {
        Self::configure_base_session(
            builder,
            DEFAULT_BUFFER_SIZE_KB,
            DEFAULT_MIN_BUFFERS,
            DEFAULT_MAX_BUFFERS,
            DEFAULT_FLUSH_TIMER_SECS,
        );

        if config.enable_process {
            Self::enable_process_monitoring(builder);
        }
        if config.enable_image_load {
            Self::enable_image_monitoring(builder);
        }
        if config.enable_threads {
            Self::enable_thread_monitoring(builder);
        }
        if config.enable_virtual_alloc {
            builder.enable_flag(KernelFlag::VirtualAlloc);
        }
        if config.enable_ob_handle {
            builder.enable_flag(KernelFlag::ObHandle);
        }
        if config.enable_syscalls {
            Self::enable_syscall_monitoring(builder);
        }
    }

    /// Composes an EDR kernel trace session from explicit `enable_syscalls` and `enable_context` toggles.
    pub fn construct_kernel_edr_session(
        builder: &mut KernelSessionBuilder,
        enable_syscalls: bool,
        enable_context: bool,
    ) {
        let config = KernelTraceConfig::new()
            .with_syscalls(enable_syscalls)
            .with_context(enable_context);
        Self::construct_kernel_session_with_config(builder, config);
    }

    /// Backwards-compatible alias for [`Self::construct_kernel_edr_session`].
    #[inline]
    pub fn construct_edr_session(
        builder: &mut KernelSessionBuilder,
        enable_syscalls: bool,
        enable_context: bool,
    ) {
        Self::construct_kernel_edr_session(builder, enable_syscalls, enable_context);
    }

    /// Configures a [`UserSessionBuilder`] with standard EDR ring-buffer sizes and registers all `providers`.
    pub fn construct_user_session(
        builder: &mut UserSessionBuilder,
        providers: impl IntoIterator<Item = Provider>,
    ) {
        Self::configure_base_session(
            builder,
            DEFAULT_BUFFER_SIZE_KB,
            DEFAULT_MIN_BUFFERS,
            DEFAULT_MAX_BUFFERS,
            DEFAULT_FLUSH_TIMER_SECS,
        );

        for provider in providers {
            builder.add_provider(provider);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sensors::etw::provider::TraceLevel;
    use crate::sensors::etw::user::UserSession;

    /// Verifies that KernelTraceConfig defaults to syscalls OFF and process/image context ON.
    #[test]
    fn test_default_kernel_trace_config_disables_syscalls() {
        let cfg = KernelTraceConfig::default();
        assert!(!cfg.enable_syscalls, "Syscalls must be disabled by default");
        assert!(cfg.enable_process);
        assert!(cfg.enable_image_load);

        let mut builder = KernelSessionBuilder::new();
        SessionDirector::construct_default_kernel_session(&mut builder);
        assert!(builder.group_mask().contains(KernelFlag::Process));
        assert!(builder.group_mask().contains(KernelFlag::ImageLoad));
        assert!(!builder.group_mask().contains(KernelFlag::SystemCall));
    }

    /// Verifies that SessionDirector properly configures kernel and user builders with standard base ring-buffer settings.
    #[test]
    fn test_director_user_and_kernel_recipes() {
        let mut kernel_builder = KernelSessionBuilder::new();
        SessionDirector::construct_kernel_edr_session(&mut kernel_builder, true, true);
        assert!(kernel_builder.group_mask().contains(KernelFlag::SystemCall));

        let mut user_builder = UserSessionBuilder::new("TestDirectorUserSession");
        let dummy_guid = GUID {
            data1: 0x1122_3344,
            data2: 0,
            data3: 0,
            data4: [0; 8],
        };
        SessionDirector::construct_user_session(
            &mut user_builder,
            vec![Provider::new("TestProv", dummy_guid).with_level(TraceLevel::Information)],
        );

        let user_session = user_builder.build().expect("Build should succeed");
        assert_eq!(UserSession::DEFAULT_SESSION_NAME, "Pulsar-User-Session");
        let _ = user_session;
    }
}
