//! Session director providing modular recipes for configuring ETW kernel sessions.

use windows_sys::Win32::System::Diagnostics::Etw::{
    EVENT_TRACE_REAL_TIME_MODE, PROCESS_TRACE_MODE_EVENT_RECORD, PROCESS_TRACE_MODE_RAW_TIMESTAMP,
};
use windows_sys::core::GUID;

use super::kernel::{KernelFlag, KernelSessionBuilder};
use super::session::EtwSessionBuilder;

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

/// Default buffer size in kilobytes for high-throughput kernel telemetry.
pub const DEFAULT_BUFFER_SIZE_KB: u32 = 1024;
/// Default minimum number of buffers in the ETW ring-buffer pool.
pub const DEFAULT_MIN_BUFFERS: u32 = 64;
/// Default maximum number of buffers in the ETW ring-buffer pool.
pub const DEFAULT_MAX_BUFFERS: u32 = 128;
/// Default forced buffer flush timer in seconds.
pub const DEFAULT_FLUSH_TIMER_SECS: u32 = 1;

/// Director helper providing composable, single-responsibility recipes for ETW kernel sessions.
pub struct SessionDirector;

impl SessionDirector {
    /// Configures the base real-time logging modes and ring-buffer allocation parameters.
    ///
    /// # Arguments
    ///
    /// * `builder` - A mutable reference to the `KernelSessionBuilder`.
    /// * `buffer_size_kb` - Buffer size in kilobytes.
    /// * `min_buffers` - Minimum number of allocated buffers in the pool.
    /// * `max_buffers` - Maximum number of allocated buffers in the pool.
    /// * `flush_timer_secs` - Interval in seconds for flushing trace buffers.
    pub fn configure_base_session(
        builder: &mut KernelSessionBuilder,
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
    ///
    /// # Arguments
    ///
    /// * `builder` - A mutable reference to the `KernelSessionBuilder`.
    pub fn enable_syscall_monitoring(builder: &mut KernelSessionBuilder) {
        builder
            .enable_flag(KernelFlag::SystemCall)
            .enable_stack_tracing(PERFINFO_GUID, EVENT_ID_SYSCALL_ENTER);
    }

    /// Enables process creation and termination telemetry.
    ///
    /// # Arguments
    ///
    /// * `builder` - A mutable reference to the `KernelSessionBuilder`.
    pub fn enable_process_monitoring(builder: &mut KernelSessionBuilder) {
        builder.enable_flag(KernelFlag::Process);
    }

    /// Enables executable and DLL image mapping/unmapping telemetry.
    ///
    /// # Arguments
    ///
    /// * `builder` - A mutable reference to the `KernelSessionBuilder`.
    pub fn enable_image_monitoring(builder: &mut KernelSessionBuilder) {
        builder.enable_flag(KernelFlag::ImageLoad);
    }

    /// Composes a tailored EDR kernel trace session based on active feature toggles
    /// using standard internal ring-buffer configurations.
    ///
    /// # Arguments
    ///
    /// * `builder` - A mutable reference to the `KernelSessionBuilder`.
    /// * `enable_syscalls` - Whether to enable system call monitoring and stack tracing.
    /// * `enable_context` - Whether to enable process and image load lifecycle telemetry.
    pub fn construct_edr_session(
        builder: &mut KernelSessionBuilder,
        enable_syscalls: bool,
        enable_context: bool,
    ) {
        Self::configure_base_session(
            builder,
            DEFAULT_BUFFER_SIZE_KB,
            DEFAULT_MIN_BUFFERS,
            DEFAULT_MAX_BUFFERS,
            DEFAULT_FLUSH_TIMER_SECS,
        );

        if enable_syscalls {
            Self::enable_syscall_monitoring(builder);
        }

        if enable_context {
            Self::enable_process_monitoring(builder);
            Self::enable_image_monitoring(builder);
        }
    }
}
