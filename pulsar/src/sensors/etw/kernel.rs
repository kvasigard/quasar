use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::SyncSender;
use std::sync::mpsc::TrySendError;
use std::thread::JoinHandle;

use super::event::EventRecord;
use super::session::{EtwSession, EtwSessionBuilder, EventTraceProperties, TraceContext};
use crate::pipeline::Event;
use crate::{AppError, win_last_error};

// Logging and Windows System APIs
use log::{debug, error, info, trace, warn};
use windows_sys::Win32::Foundation::{ERROR_ALREADY_EXISTS, ERROR_SUCCESS};
use windows_sys::Win32::System::Diagnostics::Etw::{
    CLASSIC_EVENT_ID, CONTROLTRACE_HANDLE, CloseTrace, ControlTraceW, EVENT_RECORD,
    EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_LOGFILEW, EVENT_TRACE_PROPERTIES,
    EVENT_TRACE_REAL_TIME_MODE, OpenTraceW, PROCESS_TRACE_MODE_EVENT_RECORD,
    PROCESS_TRACE_MODE_RAW_TIMESTAMP, PROCESS_TRACE_MODE_REAL_TIME, ProcessTrace, StartTraceW,
    SystemTraceControlGuid, TraceSetInformation, WNODE_FLAG_TRACED_GUID,
};
use windows_sys::core::GUID;

/// Represents the primary kernel flags used in the `EnableFlags` member of the
/// `EVENT_TRACE_PROPERTIES` structure for the NT Kernel Logger.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum KernelFlag {
    // --- Process and Thread Events ---
    /// Enables process-related events, such as process creation and termination.
    Process = 0x0000_0001,
    /// Enables thread-related events, including thread start and end.
    Thread = 0x0000_0002,
    /// Enables context switch events, which track when a processor switches between threads.
    Cswitch = 0x0000_0010,
    /// Enables thread dispatcher events, such as ReadyThread.
    Dispatcher = 0x0000_0800,
    /// Enables process performance counter events.
    ProcessCounters = 0x0000_0008,
    /// Enables events related to Windows jobs.
    Job = 0x0008_0000,

    // --- Memory and Page Fault Events ---
    /// Enables all page fault events, including transition and demand-zero faults.
    MemoryPageFaults = 0x0000_1000,
    /// Enables hard page fault events (faults requiring disk access).
    MemoryHardFaults = 0x0000_2000,
    /// Enables events for virtual memory allocation and free operations.
    VirtualAlloc = 0x0000_4000,
    /// Enables events for mapping and unmapping files (excluding image files).
    Vamap = 0x0000_8000,

    // --- I/O and Storage Events ---
    /// Enables physical disk I/O events like read, write, and flush.
    DiskIo = 0x0000_0100,
    /// Enables events that mark the beginning of a disk I/O operation.
    DiskIoInit = 0x0000_0400,
    /// Enables file I/O events that include the file name.
    /// Note: Requires EVENT_TRACE_FLAG_DISK_IO to also be set.
    DiskFileIo = 0x0000_0200,
    /// Enables high-level file system operation end times and results.
    FileIo = 0x0200_0000,
    /// Enables initialization events for file operations like create, open, and read/write.
    FileIoInit = 0x0400_0000,
    /// Enables split I/O events, indicating requests split into multiple disk I/Os.
    SplitIo = 0x0020_0000,
    /// Enables events relating to driver execution and completion of I/O request packets (IRPs).
    Driver = 0x0080_0000,

    // --- Network, Registry, and ALPC Events ---
    /// Enables TCP/IP and UDP/IP network events.
    NetworkTcpip = 0x0001_0000,
    /// Enables registry operations like create, open, and set value.
    Registry = 0x0002_0000,
    /// Enables events for Advanced Local Procedure Calls (ALPC).
    Alpc = 0x0010_0000,

    // --- Performance and Debugging Events ---
    /// Enables events for system call entry and exit.
    SystemCall = 0x0000_0080,
    /// Enables sampled profile events used for performance analysis.
    Profile = 0x0100_0000,
    /// Enables events for deferred procedure calls (DPC).
    Dpc = 0x0000_0020,
    /// Enables events for interrupt service routines (ISR).
    Interrupt = 0x0000_0040,
    /// Enables image load/unload events for executables and DLLs.
    ImageLoad = 0x0000_0004,
    /// Enables DbgPrint and DbgPrintEx calls to be captured as ETW events.
    DbgPrint = 0x0004_0000,

    // --- Configuration Flags ---
    /// Directs the logger not to perform a system configuration rundown at the start of the trace.
    /// Supported on Windows 8 and later.
    NoSysConfig = 0x1000_0000,
}

/// The static C-ABI callback invoked by Windows for every single ETW event.
///
/// # Safety
/// This function is called synchronously by the Windows kernel via `ProcessTrace`.
/// It must not block for long periods.
unsafe extern "system" fn etw_callback(record: *mut EVENT_RECORD) {
    if record.is_null() {
        return;
    }

    // SAFETY: Already checked for null
    unsafe {
        let ctx_ptr = (*record).UserContext as *mut TraceContext;
        if ctx_ptr.is_null() {
            return;
        }

        // Discard System (4), Idle (0), and our own tracer PID to avoid infinite loops
        // or processing irrelevant background OS noise.
        let process_id = (*record).EventHeader.ProcessId;
        let current_pid = (*ctx_ptr).current_pid;

        if process_id == 0 || process_id == 4 || process_id == current_pid {
            return;
        }

        // Parse and send the event to the Dispatcher.
        if let Some(event_record) = EventRecord::from_raw(record) {
            let event = Event::Etw(event_record);

            if let Err(err) = (*ctx_ptr).sender.try_send(event) {
                match err {
                    TrySendError::Full(_) => {
                        // Warn only once if the channel is full
                        if !(*ctx_ptr).channel_full_warned.swap(true, Ordering::Relaxed) {
                            log::warn!(
                                "The event channel reached its maximum capacity! Some events might be dropped..."
                            );
                        }
                    }
                    TrySendError::Disconnected(_) => {
                        // Channel dropped, gracefully ignore as shutdown is likely in progress
                    }
                }
            }
        }
    }
}

/// A simple singleton guard to ensure only one NT Kernel Logger is created.
/// Windows strictly limits the NT Kernel Logger to a single concurrent session across the entire OS.
pub struct NtKernelGuard;

static IS_TAKEN: AtomicBool = AtomicBool::new(false);

impl NtKernelGuard {
    /// Attempts to acquire the global lock for the NT Kernel Logger.
    pub fn acquire() -> Result<(), AppError> {
        // SeqCst ensures strict memory ordering, preventing race conditions if multiple
        // threads attempt to build a kernel session simultaneously.
        if IS_TAKEN
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            debug!("Successfully acquired NT Kernel Logger lock.");
            Ok(())
        } else {
            warn!("Failed to acquire NT Kernel Logger lock: Already in use.");
            Err(AppError::Internal(
                "The NT Kernel Logger is already running or acquired by another builder.".into(),
            ))
        }
    }
    /// Releases the global lock, allowing a new kernel session to be built.
    pub fn release() {
        IS_TAKEN.store(false, Ordering::SeqCst);
        debug!("Released NT Kernel Logger lock.");
    }
}

// --- Builder ---

/// Constructs the highly specific `NT Kernel Logger` configurations.
pub struct KernelSessionBuilder {
    properties: EventTraceProperties,
    flags: Vec<KernelFlag>,
    stack_tracing_events: Vec<(GUID, u8)>,
}

impl KernelSessionBuilder {
    pub fn new() -> Self {
        Self {
            properties: EventTraceProperties::default(),
            flags: Vec::new(),
            stack_tracing_events: Vec::new(),
        }
    }

    /// Enables a specific kernel flag (e.g., Process, NetworkTcpip).
    pub fn enable_flag(&mut self, flag: KernelFlag) -> &mut Self {
        if !self.flags.contains(&flag) {
            trace!("Enabling kernel flag: {:?}", flag);
            self.flags.push(flag);
        }
        self
    }

    /// Instructs the kernel logger to capture stack traces for specific Event IDs.
    ///
    /// # Parameters
    /// * `guid`: The Event Class GUID (e.g., PERFINFO_GUID).
    /// * `event_type`: The specific event type ID (e.g., 46 for SampleProfile).
    pub fn enable_stack_tracing(&mut self, guid: GUID, event_type: u8) -> &mut Self {
        // Prevent duplicate hook registrations to avoid redundant ETW stack trace overhead.
        // Using .iter().any() because windows_sys GUID does not implement PartialEq by default.
        let exists = self.stack_tracing_events.iter().any(|(g, t)| {
            g.data1 == guid.data1
                && g.data2 == guid.data2
                && g.data3 == guid.data3
                && g.data4 == guid.data4
                && *t == event_type
        });

        if !exists {
            debug!("Registering stack tracing for event type: {}", event_type);
            self.stack_tracing_events.push((guid, event_type));
        }
        self
    }

    /// Consumes the builder recipe to return the configured product.
    /// Fails if the NT Kernel Logger lock is already acquired globally.
    pub fn build(&self) -> Result<KernelSession, AppError> {
        NtKernelGuard::acquire()?;

        // Cloning avoids lifetime complexity for builder properties;
        // the overhead is negligible given the small memory footprint of these vectors.
        Ok(KernelSession {
            properties: self.properties.clone(),
            flags: self.flags.clone(),
            stack_tracing_events: self.stack_tracing_events.clone(),
            handle: None,
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

// --- Session ---

/// The resulting session object used to start/stop the NT Kernel Logger.
pub struct KernelSession {
    /// Configurable provider properties passed down from the builder.
    /// Cannot be changed after the session is started.
    properties: EventTraceProperties,
    flags: Vec<KernelFlag>,
    stack_tracing_events: Vec<(GUID, u8)>,
    handle: Option<CONTROLTRACE_HANDLE>,
}

impl KernelSession {
    pub const SESSION_NAME: &'static str = "NT Kernel Logger";

    /// Combines the enabled kernel flags into the 32-bit bitmask needed
    /// for the `EnableFlags` field in Win32 API.
    pub fn get_enable_flags_mask(&self) -> u32 {
        self.flags.iter().fold(0, |acc, flag| acc | (*flag as u32))
    }

    /// Enables stack tracing for specific events on an active ETW session.
    fn enable_stack_trace(&self) {
        if !self.stack_tracing_events.is_empty() {
            // Note: To capture kernel stacks, EVENT_TRACE_FLAG_PROFILE flag must be set
            // during StartTrace and the SeDebugPrivilege must be enabled.
            // See remarks in: https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-tracesetinformation

            for (guid, event_type) in &self.stack_tracing_events {
                // Associates a specific event provider (GUID) and event type with stack tracing.
                // Docs:
                //  - https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-classic_event_id
                //  - https://learn.microsoft.com/en-us/windows/win32/etw/nt-kernel-logger-constants
                let mut hook_id_info = CLASSIC_EVENT_ID {
                    EventGuid: *guid,
                    Type: *event_type,
                    Reserved: [0; 7],
                };

                if let Some(handle) = self.handle {
                    // SAFETY: hook_id_info is a valid CLASSIC_EVENT_ID, correctly sized.
                    let status = unsafe {
                        TraceSetInformation(
                            handle,
                            // InfoClass 3 corresponds to TraceStackTracingInfo.
                            // Docs: https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ne-evntrace-trace_info_class
                            3,
                            &mut hook_id_info as *mut _ as *const c_void,
                            std::mem::size_of::<CLASSIC_EVENT_ID>() as u32,
                        )
                    };

                    if status != ERROR_SUCCESS {
                        warn!(
                            "Failed to set stack tracing for event type {}. Error code: {}",
                            event_type, status
                        );
                    } else {
                        debug!("Stack tracing enabled for event type {}", event_type);
                    }
                }
            }
        }
    }
}

impl EtwSession for KernelSession {
    /// Starts the ETW trace session.
    ///
    /// Note: This operation requires Administrator privileges.
    fn start(&mut self) -> Result<(), AppError> {
        if self.handle.is_some() {
            error!("Attempted to start an already running NT Kernel Logger instance.");
            return Err(AppError::internal(
                "Non-null handle found when trying to initialize NT Kernel Logger",
            ));
        }

        info!("Starting ETW session: {}", Self::SESSION_NAME);

        // Windows APIs require null-terminated UTF-16 strings.
        let name_wide: Vec<u16> = Self::SESSION_NAME.encode_utf16().chain(Some(0)).collect();
        let file_wide: Vec<u16> = self
            .properties
            .log_file_name
            .as_ref()
            .map(|s| s.encode_utf16().chain(Some(0)).collect())
            .unwrap_or_default();

        let struct_size = size_of::<EVENT_TRACE_PROPERTIES>();
        let name_len_bytes = name_wide.len() * size_of::<u16>();
        let file_len_bytes = file_wide.len() * size_of::<u16>();

        // ETW expects a single contiguous block of memory containing the properties struct
        // immediately followed by the session name and the optional log file name.
        let total_size = struct_size + name_len_bytes + file_len_bytes;

        // Using Vec<u8> ensures heap allocation. Blocks > 16 bytes are 16-byte aligned in Rust,
        // which perfectly satisfies the 8-byte alignment requirement for WNODE_HEADER.
        let mut buffer = vec![0u8; total_size];
        let props_ptr = buffer.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;

        // SAFETY: The buffer is guaranteed to be large enough (total_size) and memory-aligned.
        // We initialize the fields required by ETW before passing the pointer to StartTraceW.
        unsafe {
            // ref: https://learn.microsoft.com/en-us/windows/win32/etw/wnode-header
            (*props_ptr).Wnode.BufferSize = total_size as u32;
            (*props_ptr).Wnode.Flags = WNODE_FLAG_TRACED_GUID;
            (*props_ptr).Wnode.ClientContext = 1; // Directs ETW to use QPC (QueryPerformanceCounter) as timestamp
            (*props_ptr).Wnode.Guid = SystemTraceControlGuid;

            // Fallback to EVENT_TRACE_REAL_TIME_MODE to prevent Error 161 (Invalid Path)
            // if no file path was provided but sequential logging was assumed.
            let mut log_mode = self.properties.log_file_mode;
            if log_mode == 0 && file_wide.is_empty() {
                warn!("Logging mode or file is not defined. Falling back to Real Time mode...");
                log_mode = EVENT_TRACE_REAL_TIME_MODE;
            }

            // ref: https://learn.microsoft.com/en-us/windows/win32/etw/logging-mode-constants
            (*props_ptr).LogFileMode = log_mode;

            // ref: https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_properties
            (*props_ptr).BufferSize = self.properties.buffer_size;
            (*props_ptr).MinimumBuffers = self.properties.minimum_buffers;
            (*props_ptr).MaximumBuffers = self.properties.maximum_buffers;
            (*props_ptr).FlushTimer = self.properties.flush_timer;
            (*props_ptr).EnableFlags = self.get_enable_flags_mask();

            // Offsets instruct Windows where to find the strings within our contiguous buffer.
            (*props_ptr).LoggerNameOffset = struct_size as u32;

            if !file_wide.is_empty() {
                (*props_ptr).LogFileNameOffset = (struct_size + name_len_bytes) as u32;
            }

            // Append the UTF-16 string data into the buffer right after the struct data.
            std::ptr::copy_nonoverlapping(
                name_wide.as_ptr(),
                buffer.as_mut_ptr().add(struct_size) as *mut u16,
                name_wide.len(),
            );

            if !file_wide.is_empty() {
                std::ptr::copy_nonoverlapping(
                    file_wide.as_ptr(),
                    buffer.as_mut_ptr().add(struct_size + name_len_bytes) as *mut u16,
                    file_wide.len(),
                );
            }

            let mut handle = CONTROLTRACE_HANDLE { Value: 0 };
            let mut status = StartTraceW(&mut handle, name_wide.as_ptr(), props_ptr);

            if status == ERROR_ALREADY_EXISTS {
                warn!("Kernel trace session already exists. Attempting to stop and recreate it...");

                // ControlTraceW overwrites the EVENT_TRACE_PROPERTIES buffer upon return.
                // We clone the buffer so we don't corrupt our configuration for the restart attempt.
                let mut stop_buffer = buffer.clone();
                let stop_props_ptr = stop_buffer.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;

                ControlTraceW(
                    CONTROLTRACE_HANDLE { Value: 0 },
                    name_wide.as_ptr(),
                    stop_props_ptr,
                    EVENT_TRACE_CONTROL_STOP,
                );

                // Retry starting the trace now that the previous session is terminated.
                status = StartTraceW(&mut handle, name_wide.as_ptr(), props_ptr);
            }

            if status == ERROR_SUCCESS {
                debug!("Successfully started ETW trace session.");
                self.handle = Some(handle);
                self.enable_stack_trace();
            } else {
                error!(
                    "Failed to start trace session. Windows Error Code: {}",
                    status
                );
                return Err(win_last_error!());
            }
        }

        Ok(())
    }

    /// Stops the ETW trace session and releases the global hardware lock.
    /// This method is idempotent; it is safe to call multiple times.
    fn stop(&mut self) -> Result<(), AppError> {
        let handle = match self.handle {
            Some(h) => h,
            None => {
                trace!("Stop called on an uninitialized session. Ignoring.");
                return Ok(());
            }
        };

        info!("Stopping ETW session...");

        // ETW requires a properly sized properties buffer to write final session statistics into
        // even when simply stopping the session.
        let name_wide: Vec<u16> = Self::SESSION_NAME.encode_utf16().chain(Some(0)).collect();
        let struct_size = size_of::<EVENT_TRACE_PROPERTIES>();
        let name_len_bytes = name_wide.len() * size_of::<u16>();

        let total_size = struct_size + name_len_bytes;
        let mut buffer = vec![0u8; total_size];
        let props_ptr = buffer.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;

        // SAFETY: Buffer is properly allocated and correctly sized to receive session shutdown data.
        unsafe {
            (*props_ptr).Wnode.BufferSize = total_size as u32;
            (*props_ptr).Wnode.Guid = SystemTraceControlGuid;
            (*props_ptr).LoggerNameOffset = struct_size as u32;

            let status = ControlTraceW(
                handle,
                std::ptr::null(), // Null is valid here since we identify the session via its handle
                props_ptr,
                EVENT_TRACE_CONTROL_STOP,
            );

            if status != ERROR_SUCCESS {
                error!(
                    "Failed to stop trace session. Windows Error Code: {}",
                    status
                );
                return Err(win_last_error!());
            }
        }

        // Zero out the handle so subsequent calls to stop() safely do nothing.
        self.handle = None;

        // Release the global lock so another Kernel Logger can be spun up later.
        NtKernelGuard::release();
        debug!("ETW session stopped successfully.");

        Ok(())
    }

    /// Spawns a background thread to consume events from the real-time trace session.
    /// Returns a JoinHandle so the caller can optionally wait for the thread to exit.
    fn consume(
        &self,
        sender: SyncSender<Event>,
    ) -> Result<JoinHandle<Result<(), AppError>>, AppError> {
        if self.handle.is_none() {
            error!("Attempted to consume events from an unstarted ETW session.");
            return Err(AppError::Internal(
                "Cannot consume from an unstarted session.".into(),
            ));
        }

        info!("Spawning background event consumption thread...");

        // We copy the session name into an owned string.
        // This allows us to move it into the thread closure without borrowing `self`.
        let session_name_owned = Self::SESSION_NAME.to_string();

        let handle = std::thread::spawn(move || {
            let mut name_wide: Vec<u16> =
                session_name_owned.encode_utf16().chain(Some(0)).collect();
            let mut context = TraceContext::new(sender);
            let mut logfile: EVENT_TRACE_LOGFILEW = unsafe { std::mem::zeroed() };

            logfile.LoggerName = name_wide.as_mut_ptr();
            logfile.Anonymous1.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME
                | PROCESS_TRACE_MODE_EVENT_RECORD
                | PROCESS_TRACE_MODE_RAW_TIMESTAMP;
            logfile.Anonymous2.EventRecordCallback = Some(etw_callback);
            logfile.Context = &mut context as *mut _ as *mut c_void;

            unsafe {
                let trace_handle = OpenTraceW(&mut logfile);

                if trace_handle.Value == 0xFFFFFFFFFFFFFFFF || trace_handle.Value == 0 {
                    return Err(win_last_error!());
                }

                debug!("Blocking ProcessTrace loop started in background thread.");

                // This blocks the background thread until kernel_session.stop() is called
                // from the main thread (or another controller thread).
                let status =
                    ProcessTrace(&trace_handle, 1, std::ptr::null_mut(), std::ptr::null_mut());

                CloseTrace(trace_handle);

                if status != ERROR_SUCCESS {
                    return Err(win_last_error!());
                }
            }

            info!("ETW consumer thread exited gracefully.");
            Ok(())
        });

        Ok(handle)
    }
}

/// Uses RAII to ensure the NT Kernel Logger releases its global lock
/// and does not orphan the Windows kernel session if the struct goes out of scope or panics.
impl Drop for KernelSession {
    fn drop(&mut self) {
        // We explicitly ignore the Result. Panicking inside Drop is dangerous
        // as it will lead to an application abort if the thread is already unwinding.
        let _ = self.stop();
    }
}
