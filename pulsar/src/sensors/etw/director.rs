use windows_sys::Win32::System::Diagnostics::Etw::{
    EVENT_TRACE_REAL_TIME_MODE, PROCESS_TRACE_MODE_EVENT_RECORD, PROCESS_TRACE_MODE_RAW_TIMESTAMP,
};
use windows_sys::core::GUID;

use super::kernel::{KernelFlag, KernelSessionBuilder};
use super::session::EtwSessionBuilder;

/// Defines the GUID for Performance Information events.
///
/// If you need to know which events can be enabled in `TraceSetInformation`,
/// refer to the NT Kernel Logger Constants documentation. It details the GUID
/// and available EventTypes for each category.
/// Docs: https://learn.microsoft.com/en-us/windows/win32/etw/nt-kernel-logger-constants
pub const PERFINFO_GUID: GUID = GUID {
    data1: 0xce1dbfb4,
    data2: 0x137e,
    data3: 0x4da6,
    data4: [0x87, 0xb0, 0x3f, 0x59, 0xaa, 0x10, 0x2c, 0xbc],
};

pub struct SessionDirector;

impl SessionDirector {
    /// Constructs a specialized monitor for System Calls with stack tracing.
    ///
    /// This method encapsulates the 'recipe' for syscall monitoring, ensuring
    /// buffer sizes and kernel flags are consistent with high-frequency event capture.
    pub fn construct_syscall_monitor(builder: &mut KernelSessionBuilder) {
        builder
            .set_log_file_mode(
                EVENT_TRACE_REAL_TIME_MODE
                    | PROCESS_TRACE_MODE_EVENT_RECORD
                    | PROCESS_TRACE_MODE_RAW_TIMESTAMP,
            )
            // Enable the emission of Syscall ETW events
            .enable_flag(KernelFlag::SystemCall)
            // .enable_flag(KernelFlag::Process)
            // .enable_flag(KernelFlag::Thread)
            // .enable_flag(KernelFlag::ImageLoad)
            // Register the specific Event IDs for stack tracing:
            // 51 corresponds to SysClEnter (System Call Entry)
            .enable_stack_tracing(PERFINFO_GUID, 51)
            // High-frequency events require substantial buffering to avoid dropped events.
            .set_buffer_size(1024)
            .set_min_buffers(64)
            .set_max_buffers(128)
            .set_flush_timer(1);
    }
}
