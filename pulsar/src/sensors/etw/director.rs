//! Session director providing modular recipes for configuring ETW kernel and user sessions.

use windows_sys::Win32::System::Diagnostics::Etw::{
    EVENT_TRACE_REAL_TIME_MODE, PROCESS_TRACE_MODE_EVENT_RECORD, PROCESS_TRACE_MODE_RAW_TIMESTAMP,
};
use windows_sys::core::GUID;

use super::kernel::{KernelFlag, KernelSessionBuilder};
use super::provider::Provider;
use super::session::EtwSessionBuilder;
use super::user::UserSessionBuilder;

/// Defines the GUID for Performance Information events (`{ce1dbfb4-137e-4da6-87b0-3f59aa102cbc}`).
///
/// Reference: <https://learn.microsoft.com/en-us/windows/win32/etw/nt-kernel-logger-constants>
pub const PERFINFO_GUID: GUID = GUID {
    data1: 0xce1dbfb4,
    data2: 0x137e,
    data3: 0x4da6,
    data4: [0x87, 0xb0, 0x3f, 0x59, 0xaa, 0x10, 0x2c, 0xbc],
};

/// Event ID for System Call Entry (`SysClEnter`) used in ETW stack tracing.
pub const EVENT_ID_SYSCALL_ENTER: u8 = 51;

/// Default buffer size in kilobytes for high-throughput kernel and user telemetry.
pub const DEFAULT_BUFFER_SIZE_KB: u32 = 1024;
/// Default minimum number of buffers in the ETW ring-buffer pool.
pub const DEFAULT_MIN_BUFFERS: u32 = 64;
/// Default maximum number of buffers in the ETW ring-buffer pool.
pub const DEFAULT_MAX_BUFFERS: u32 = 128;
/// Default forced buffer flush timer in seconds.
pub const DEFAULT_FLUSH_TIMER_SECS: u32 = 1;

/// Declarative configuration profile for the System Logger V2 [`KernelSession`](super::kernel::KernelSession).
///
/// By default, process and image-load context telemetry are enabled while high-volume
/// system call telemetry (`enable_syscalls`) is **disabled** (`false`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KernelTraceConfig {
    /// Enable process creation, termination, and rundown telemetry (`PERF_PROCESS`).
    pub enable_process: bool,
    /// Enable executable and DLL image load/unload telemetry (`PERF_IMAGE_LOAD`).
    pub enable_image_load: bool,
    /// Enable thread creation, termination, and rundown telemetry (`PERF_THREAD`).
    pub enable_threads: bool,
    /// Enable virtual memory allocation/free telemetry (`PERF_VIRTUAL_ALLOC`).
    pub enable_virtual_alloc: bool,
    /// Enable Object Manager handle operation telemetry (`PERF_OB_HANDLE`).
    pub enable_ob_handle: bool,
    /// Enable kernel system call (`SysCallEnter`) and stack walk telemetry (`PERF_SYSCALL`).
    /// Disabled (`false`) by default due to extreme event volume.
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
    /// Creates the default EDR kernel trace profile (Process + ImageLoad enabled, Syscalls disabled).
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

    /// Toggles process and image load context tracing.
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

/// Director helper providing composable, single-responsibility recipes for ETW sessions.
pub struct SessionDirector;

impl SessionDirector {
    /// Configures the base real-time logging modes and ring-buffer allocation parameters
    /// polymorphically on any builder implementing [`EtwSessionBuilder`].
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

    /// Enables kernel system call event emission and kernel-level stack walk tracing.
    pub fn enable_syscall_monitoring(builder: &mut KernelSessionBuilder) {
        builder
            .enable_flag(KernelFlag::SystemCall)
            .enable_stack_tracing(PERFINFO_GUID, EVENT_ID_SYSCALL_ENTER);
    }

    /// Enables process creation and termination telemetry.
    pub fn enable_process_monitoring(builder: &mut KernelSessionBuilder) {
        builder.enable_flag(KernelFlag::Process);
    }

    /// Enables executable and DLL image mapping/unmapping telemetry.
    pub fn enable_image_monitoring(builder: &mut KernelSessionBuilder) {
        builder.enable_flag(KernelFlag::ImageLoad);
    }

    /// Enables thread creation and termination telemetry.
    pub fn enable_thread_monitoring(builder: &mut KernelSessionBuilder) {
        builder.enable_flag(KernelFlag::Thread);
    }

    /// Configures a [`KernelSessionBuilder`] using the default [`KernelTraceConfig`]
    /// (Process + ImageLoad enabled, Syscalls disabled by default).
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

    /// Composes a tailored EDR kernel trace session based on active feature toggles
    /// using standard internal ring-buffer configurations.
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

    /// Composes a tailored user-mode trace session with standard ring-buffers and registered providers.
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
