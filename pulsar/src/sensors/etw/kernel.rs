//! NT Kernel Logger ETW sensor implementation and ring-buffer management.

use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::SyncSender;
use std::sync::mpsc::TrySendError;
use std::thread::JoinHandle;

use super::event::EventRecord;
use super::session::{EtwSession, EtwSessionBuilder, EventTraceProperties, TraceContext};
use crate::pipeline::Event;
use crate::{AppError, win_last_error};

// Windows System APIs
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
    NoSysConfig = 0x1000_0000,
}

/// The static C-ABI callback invoked synchronously by Windows via `ProcessTrace`.
///
/// # Safety
///
/// `record` must be a valid pointer to an `EVENT_RECORD` provided by the ETW runtime.
unsafe extern "system" fn etw_callback(record: *mut EVENT_RECORD) {
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
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
                                    target: "etw_kernel",
                                    "The event channel reached its maximum capacity. Some events might be dropped."
                                );
                            }
                        }
                        TrySendError::Disconnected(_) => {
                            // Channel dropped, gracefully ignore as shutdown is in progress
                        }
                    }
                }
            }
        }
    }));
}

/// Singleton guard ensuring only one NT Kernel Logger is created concurrently.
/// Windows strictly limits the NT Kernel Logger to a single concurrent session across the entire OS.
pub struct NtKernelGuard;

static IS_TAKEN: AtomicBool = AtomicBool::new(false);

impl NtKernelGuard {
    /// Attempts to acquire the global lock for the NT Kernel Logger.
    ///
    /// # Returns
    ///
    /// `Ok(())` on successful atomic acquisition, or `Err(AppError)` if already active.
    ///
    /// # Errors
    ///
    /// Returns `AppError::Internal` if another session has locked the NT Kernel Logger.
    pub fn acquire() -> Result<(), AppError> {
        if IS_TAKEN
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            log::debug!(target: "etw_kernel", "Successfully acquired NT Kernel Logger lock.");
            Ok(())
        } else {
            log::warn!(target: "etw_kernel", "Failed to acquire NT Kernel Logger lock: Already in use.");
            Err(AppError::Internal(
                "The NT Kernel Logger is already running or acquired by another builder.".into(),
            ))
        }
    }

    /// Releases the global lock, allowing a new kernel session to be built.
    pub fn release() {
        IS_TAKEN.store(false, Ordering::SeqCst);
        log::debug!(target: "etw_kernel", "Released NT Kernel Logger lock.");
    }
}

// --- Builder ---

/// Constructs `NT Kernel Logger` configurations with specific event flags and stack tracing.
pub struct KernelSessionBuilder {
    properties: EventTraceProperties,
    flags: Vec<KernelFlag>,
    stack_tracing_events: Vec<(GUID, u8)>,
}

impl Default for KernelSessionBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl KernelSessionBuilder {
    /// Creates a new `KernelSessionBuilder` with default buffering properties.
    ///
    /// # Returns
    ///
    /// An empty `KernelSessionBuilder`.
    pub fn new() -> Self {
        Self {
            properties: EventTraceProperties::default(),
            flags: Vec::new(),
            stack_tracing_events: Vec::new(),
        }
    }

    /// Enables a specific kernel flag (e.g. `KernelFlag::Process`, `KernelFlag::SystemCall`).
    ///
    /// # Arguments
    ///
    /// * `flag` - The `KernelFlag` to activate.
    ///
    /// # Returns
    ///
    /// A mutable reference to `self` for method chaining.
    pub fn enable_flag(&mut self, flag: KernelFlag) -> &mut Self {
        if !self.flags.contains(&flag) {
            log::trace!(target: "etw_kernel", "Enabling kernel flag: {:?}", flag);
            self.flags.push(flag);
        }
        self
    }

    /// Instructs the kernel logger to capture call stack traces for specific Event IDs.
    ///
    /// # Arguments
    ///
    /// * `guid` - The Event Class GUID (e.g. `PERFINFO_GUID`).
    /// * `event_type` - The specific event type ID (e.g. `51` for `SysClEnter`).
    ///
    /// # Returns
    ///
    /// A mutable reference to `self` for method chaining.
    pub fn enable_stack_tracing(&mut self, guid: GUID, event_type: u8) -> &mut Self {
        let exists = self.stack_tracing_events.iter().any(|(g, t)| {
            g.data1 == guid.data1
                && g.data2 == guid.data2
                && g.data3 == guid.data3
                && g.data4 == guid.data4
                && *t == event_type
        });

        if !exists {
            log::debug!(target: "etw_kernel", "Registering stack tracing for event type: {}", event_type);
            self.stack_tracing_events.push((guid, event_type));
        }
        self
    }

    /// Consumes the builder recipe to produce a configured `KernelSession`.
    ///
    /// # Returns
    ///
    /// An initialized `KernelSession` ready to `start()`.
    ///
    /// # Errors
    ///
    /// Returns `AppError::Internal` if the global NT Kernel Logger lock cannot be acquired.
    pub fn build(&self) -> Result<KernelSession, AppError> {
        NtKernelGuard::acquire()?;

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

/// Active or configured session object managing the lifecycle of the NT Kernel Logger.
pub struct KernelSession {
    properties: EventTraceProperties,
    flags: Vec<KernelFlag>,
    stack_tracing_events: Vec<(GUID, u8)>,
    handle: Option<CONTROLTRACE_HANDLE>,
}

impl KernelSession {
    /// Canonical name for the NT Kernel Logger ETW session.
    pub const SESSION_NAME: &'static str = "NT Kernel Logger";

    /// Combines enabled kernel flags into the 32-bit bitmask needed for Win32 API.
    ///
    /// # Returns
    ///
    /// Combined 32-bit flag bitmask.
    pub fn get_enable_flags_mask(&self) -> u32 {
        self.flags.iter().fold(0, |acc, flag| acc | (*flag as u32))
    }

    /// Configures kernel stack tracing hooks via `TraceSetInformation`.
    fn enable_stack_trace(&self) {
        if !self.stack_tracing_events.is_empty() {
            for (guid, event_type) in &self.stack_tracing_events {
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
                            3, // InfoClass 3: TraceStackTracingInfo
                            &mut hook_id_info as *mut _ as *const c_void,
                            std::mem::size_of::<CLASSIC_EVENT_ID>() as u32,
                        )
                    };

                    if status != ERROR_SUCCESS {
                        log::warn!(
                            target: "etw_kernel",
                            "Failed to set stack tracing for event type {}. Error code: {}",
                            event_type, status
                        );
                    } else {
                        log::debug!(target: "etw_kernel", "Stack tracing enabled for event type {}", event_type);
                    }
                }
            }
        }
    }
}

impl EtwSession for KernelSession {
    /// Starts the ETW trace session with the Windows kernel.
    ///
    /// Requires Administrator privileges.
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, or `Err(AppError)` if starting fails.
    ///
    /// # Errors
    ///
    /// Returns `AppError::Internal` or `AppError::WindowsApi` on error.
    fn start(&mut self) -> Result<(), AppError> {
        if self.handle.is_some() {
            log::warn!(target: "etw_kernel", "Attempted to start an already running NT Kernel Logger instance.");
            return Err(AppError::internal(
                "Non-null handle found when trying to initialize NT Kernel Logger",
            ));
        }

        log::info!(target: "etw_kernel", "Starting ETW session: {}", Self::SESSION_NAME);

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

        let total_size = struct_size + name_len_bytes + file_len_bytes;
        let mut buffer = vec![0u8; total_size];
        let props_ptr = buffer.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;

        // SAFETY: Buffer is properly sized and aligned for EVENT_TRACE_PROPERTIES.
        unsafe {
            (*props_ptr).Wnode.BufferSize = total_size as u32;
            (*props_ptr).Wnode.Flags = WNODE_FLAG_TRACED_GUID;
            (*props_ptr).Wnode.ClientContext = 1; // QPC timestamp
            (*props_ptr).Wnode.Guid = SystemTraceControlGuid;

            let mut log_mode = self.properties.log_file_mode;
            if log_mode == 0 && file_wide.is_empty() {
                log::warn!(target: "etw_kernel", "Logging mode or file is not defined. Falling back to Real Time mode.");
                log_mode = EVENT_TRACE_REAL_TIME_MODE;
            }

            (*props_ptr).LogFileMode = log_mode;
            (*props_ptr).BufferSize = self.properties.buffer_size;
            (*props_ptr).MinimumBuffers = self.properties.minimum_buffers;
            (*props_ptr).MaximumBuffers = self.properties.maximum_buffers;
            (*props_ptr).FlushTimer = self.properties.flush_timer;
            (*props_ptr).EnableFlags = self.get_enable_flags_mask();
            (*props_ptr).LoggerNameOffset = struct_size as u32;

            if !file_wide.is_empty() {
                (*props_ptr).LogFileNameOffset = (struct_size + name_len_bytes) as u32;
            }

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
                log::warn!(target: "etw_kernel", "Kernel trace session already exists. Attempting to stop and recreate it...");

                let mut stop_buffer = buffer.clone();
                let stop_props_ptr = stop_buffer.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;

                ControlTraceW(
                    CONTROLTRACE_HANDLE { Value: 0 },
                    name_wide.as_ptr(),
                    stop_props_ptr,
                    EVENT_TRACE_CONTROL_STOP,
                );

                status = StartTraceW(&mut handle, name_wide.as_ptr(), props_ptr);
            }

            if status == ERROR_SUCCESS {
                log::debug!(target: "etw_kernel", "Successfully started ETW trace session.");
                self.handle = Some(handle);
                self.enable_stack_trace();
            } else {
                log::error!(
                    target: "etw_kernel",
                    "Failed to start trace session. Windows Error Code: {}",
                    status
                );
                return Err(win_last_error!());
            }
        }

        Ok(())
    }

    /// Stops the ETW trace session and releases the global hardware lock.
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, or `Err(AppError)` on failure.
    ///
    /// # Errors
    ///
    /// Returns `AppError::WindowsApi` if `ControlTraceW` fails.
    fn stop(&mut self) -> Result<(), AppError> {
        let handle = match self.handle {
            Some(h) => h,
            None => {
                log::trace!(target: "etw_kernel", "Stop called on an uninitialized session. Ignoring.");
                return Ok(());
            }
        };

        log::info!(target: "etw_kernel", "Stopping ETW session...");

        let name_wide: Vec<u16> = Self::SESSION_NAME.encode_utf16().chain(Some(0)).collect();
        let struct_size = size_of::<EVENT_TRACE_PROPERTIES>();
        let name_len_bytes = name_wide.len() * size_of::<u16>();

        let total_size = struct_size + name_len_bytes;
        let mut buffer = vec![0u8; total_size];
        let props_ptr = buffer.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;

        // SAFETY: Buffer is properly allocated and correctly sized.
        unsafe {
            (*props_ptr).Wnode.BufferSize = total_size as u32;
            (*props_ptr).Wnode.Guid = SystemTraceControlGuid;
            (*props_ptr).LoggerNameOffset = struct_size as u32;

            let status = ControlTraceW(
                handle,
                std::ptr::null(),
                props_ptr,
                EVENT_TRACE_CONTROL_STOP,
            );

            if status != ERROR_SUCCESS {
                log::error!(
                    target: "etw_kernel",
                    "Failed to stop trace session. Windows Error Code: {}",
                    status
                );
                return Err(win_last_error!());
            }
        }

        self.handle = None;
        NtKernelGuard::release();
        log::debug!(target: "etw_kernel", "ETW session stopped successfully.");

        Ok(())
    }

    /// Spawns a background thread consuming event records via `ProcessTrace`.
    ///
    /// # Arguments
    ///
    /// * `sender` - The channel sender forwarding parsed events to the dispatcher.
    ///
    /// # Returns
    ///
    /// A `JoinHandle` for the consumer thread.
    ///
    /// # Errors
    ///
    /// Returns `AppError::Internal` if the session is not started, or `AppError::WindowsApi` if `OpenTraceW` fails.
    fn consume(
        &self,
        sender: SyncSender<Event>,
    ) -> Result<JoinHandle<Result<(), AppError>>, AppError> {
        if self.handle.is_none() {
            log::warn!(target: "etw_kernel", "Attempted to consume events from an unstarted ETW session.");
            return Err(AppError::Internal(
                "Cannot consume from an unstarted session.".into(),
            ));
        }

        log::info!(target: "etw_kernel", "Spawning background event consumption thread...");

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

                log::debug!(target: "etw_kernel", "Blocking ProcessTrace loop started in background thread.");

                let status =
                    ProcessTrace(&trace_handle, 1, std::ptr::null_mut(), std::ptr::null_mut());

                CloseTrace(trace_handle);

                if status != ERROR_SUCCESS {
                    return Err(win_last_error!());
                }
            }

            log::info!(target: "etw_kernel", "ETW consumer thread exited gracefully.");
            Ok(())
        });

        Ok(handle)
    }
}

/// RAII implementation ensuring NT Kernel Logger releases its global lock on drop.
impl Drop for KernelSession {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}
