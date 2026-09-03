//! NT Kernel Logger ETW sensor implementation and ring-buffer management.

use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::SyncSender;
use std::thread::JoinHandle;

use super::consumer::spawn_trace_consumer;
use super::error::EtwError;
use super::event::EventRecord;
use super::properties::TracePropertiesBuffer;
use super::session::{EtwSession, EtwSessionBuilder, EventTraceProperties};

// Windows System APIs
use windows_sys::Win32::Foundation::{ERROR_ALREADY_EXISTS, ERROR_SUCCESS};
use windows_sys::Win32::System::Diagnostics::Etw::{
    CLASSIC_EVENT_ID, CONTROLTRACE_HANDLE, ControlTraceW, EVENT_TRACE_CONTROL_STOP, StartTraceW,
    SystemTraceControlGuid, TraceSetInformation,
};
use windows_sys::core::GUID;

/// Represents the primary kernel flags used in the `EnableFlags` member of the
/// `EVENT_TRACE_PROPERTIES` structure.
///
/// Setting these flags tells the kernel to enable event tracing for specific
/// kernel subsystems.
///
/// Reference: <https://learn.microsoft.com/en-us/windows/win32/etw/event-trace-properties>
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelFlag {
    // --- Process & Thread Events ---
    /// Enables process tracing (creation, termination, data collection).
    Process = 0x0000_0001,
    /// Enables thread tracing (creation, termination, context switch).
    Thread = 0x0000_0002,
    /// Enables image load tracing (DLL/Driver loading/unloading).
    ImageLoad = 0x0000_0004,
    /// Enables process counter tracing.
    ProcessCounter = 0x0000_0008,

    // --- Memory & Disk Events ---
    /// Enables disk I/O tracing.
    DiskIO = 0x0000_0100,
    /// Enables file I/O operations (detailed file access).
    DiskFileIO = 0x0000_0200,
    /// Enables memory page faults and hard fault tracing.
    PageFault = 0x0000_1000,
    /// Enables hard fault tracing.
    HardFault = 0x0000_2000,

    // --- Network Events ---
    /// Enables TCP and UDP IP tracing.
    NetworkTCPIP = 0x0001_0000,

    // --- Registry & Inter-Process Communication ---
    /// Enables registry access (open, create, query, set key).
    Registry = 0x0002_0000,
    /// Enables Advanced Local Procedure Call (ALPC) tracing.
    Alpc = 0x0010_0000,
    /// Enables Object Manager tracking (Handles, Object creation/destruction).
    Handle = 0x8000_0000,

    // --- System & Hardware Activity ---
    /// Enables kernel system call tracing (SysEnter / SysExit).
    SystemCall = 0x0000_0080,
    /// Enables Interrupt Service Routine (ISR) and Deferred Procedure Call (DPC) tracing.
    Dispatcher = 0x0000_0800,
    /// Enables Virtual Allocation / Memory management operations.
    VirtualAlloc = 0x0000_4000,
    /// Enables debug print tracing (`DbgPrint`).
    DbgPrint = 0x0004_0000,

    // --- Configuration Flags ---
    /// Directs the logger not to perform a system configuration rundown at the start of the trace.
    NoSysConfig = 0x1000_0000,
}

/// Singleton RAII guard ensuring only one NT Kernel Logger session is active concurrently across the OS.
/// Releasing the guard on drop automatically frees the global atomic lock, preventing poisoning on panic.
pub struct NtKernelGuard(());

static IS_TAKEN: AtomicBool = AtomicBool::new(false);

impl NtKernelGuard {
    /// Attempts to acquire the global lock for the NT Kernel Logger.
    pub fn acquire() -> Result<Self, EtwError> {
        if IS_TAKEN
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            log::debug!(target: "etw_kernel", "Successfully acquired NT Kernel Logger lock.");
            Ok(Self(()))
        } else {
            log::warn!(target: "etw_kernel", "Failed to acquire NT Kernel Logger lock: Already in use.");
            Err(EtwError::KernelLoggerAlreadyActive)
        }
    }
}

impl Drop for NtKernelGuard {
    fn drop(&mut self) {
        IS_TAKEN.store(false, Ordering::SeqCst);
        log::debug!(target: "etw_kernel", "Released NT Kernel Logger lock via RAII guard.");
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
    /// Returns [`EtwError::KernelLoggerAlreadyActive`] if the global NT Kernel Logger lock cannot be acquired.
    pub fn build(&self) -> Result<KernelSession, EtwError> {
        let guard = NtKernelGuard::acquire()?;

        Ok(KernelSession {
            properties: self.properties.clone(),
            flags: self.flags.clone(),
            stack_tracing_events: self.stack_tracing_events.clone(),
            handle: None,
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

// --- Session ---

/// Active or configured session object managing the lifecycle of the NT Kernel Logger.
pub struct KernelSession {
    properties: EventTraceProperties,
    flags: Vec<KernelFlag>,
    stack_tracing_events: Vec<(GUID, u8)>,
    handle: Option<CONTROLTRACE_HANDLE>,
    _guard: Option<NtKernelGuard>,
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
    /// `Ok(())` on success, or `Err(EtwError)` if starting fails.
    ///
    /// # Errors
    ///
    /// Returns [`EtwError::SessionAlreadyRunning`] or [`EtwError::WindowsApi`] on error.
    fn start(&mut self) -> Result<(), EtwError> {
        if self.handle.is_some() {
            log::warn!(target: "etw_kernel", "Attempted to start an already running NT Kernel Logger instance.");
            return Err(EtwError::SessionAlreadyRunning(
                Self::SESSION_NAME.to_string(),
            ));
        }

        log::info!(target: "etw_kernel", "Starting ETW session: {}", Self::SESSION_NAME);

        let name_wide: Vec<u16> = Self::SESSION_NAME.encode_utf16().chain(Some(0)).collect();
        let mut props_buf = TracePropertiesBuffer::new(
            Self::SESSION_NAME,
            &self.properties,
            SystemTraceControlGuid,
            self.get_enable_flags_mask(),
        );

        let mut handle = CONTROLTRACE_HANDLE { Value: 0 };
        let mut status = unsafe {
            StartTraceW(&mut handle, name_wide.as_ptr(), props_buf.as_mut_ptr())
        };

        if status == ERROR_ALREADY_EXISTS {
            log::warn!(target: "etw_kernel", "Kernel trace session already exists. Attempting to stop and recreate it...");

            let mut stop_buf = TracePropertiesBuffer::new(
                Self::SESSION_NAME,
                &self.properties,
                SystemTraceControlGuid,
                0,
            );

            unsafe {
                ControlTraceW(
                    CONTROLTRACE_HANDLE { Value: 0 },
                    name_wide.as_ptr(),
                    stop_buf.as_mut_ptr(),
                    EVENT_TRACE_CONTROL_STOP,
                );

                status = StartTraceW(&mut handle, name_wide.as_ptr(), props_buf.as_mut_ptr());
            }
        }

        if status == ERROR_SUCCESS {
            log::debug!(target: "etw_kernel", "Successfully started ETW trace session.");
            self.handle = Some(handle);
            self.enable_stack_trace();
            Ok(())
        } else {
            log::error!(
                target: "etw_kernel",
                "Failed to start trace session. Windows Error Code: {}",
                status
            );
            Err(EtwError::from_win32_code(status))
        }
    }

    /// Stops the ETW trace session and releases the global hardware lock.
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, or `Err(EtwError)` on failure.
    ///
    /// # Errors
    ///
    /// Returns [`EtwError::WindowsApi`] if `ControlTraceW` fails.
    fn stop(&mut self) -> Result<(), EtwError> {
        let handle = match self.handle.take() {
            Some(h) => h,
            None => {
                log::trace!(target: "etw_kernel", "Stop called on an uninitialized session. Ignoring.");
                self._guard = None;
                return Ok(());
            }
        };

        log::info!(target: "etw_kernel", "Stopping ETW session...");

        let name_wide: Vec<u16> = Self::SESSION_NAME.encode_utf16().chain(Some(0)).collect();
        let mut props_buf = TracePropertiesBuffer::new(
            Self::SESSION_NAME,
            &self.properties,
            SystemTraceControlGuid,
            0,
        );

        let status = unsafe {
            ControlTraceW(
                handle,
                name_wide.as_ptr(),
                props_buf.as_mut_ptr(),
                EVENT_TRACE_CONTROL_STOP,
            )
        };

        self._guard = None;

        if status != ERROR_SUCCESS {
            log::error!(
                target: "etw_kernel",
                "Failed to stop trace session. Windows Error Code: {}",
                status
            );
            return Err(EtwError::from_win32_code(status));
        }

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
    /// Returns [`EtwError::SessionNotStarted`] if the session is not started, or [`EtwError::WindowsApi`] if `OpenTraceW` fails.
    fn consume(
        &self,
        sender: SyncSender<EventRecord>,
    ) -> Result<JoinHandle<Result<(), EtwError>>, EtwError> {
        if self.handle.is_none() {
            log::warn!(target: "etw_kernel", "Attempted to consume events from an unstarted ETW session.");
            return Err(EtwError::SessionNotStarted(
                Self::SESSION_NAME.to_string(),
            ));
        }

        spawn_trace_consumer(Self::SESSION_NAME.to_string(), sender)
    }
}

/// RAII implementation ensuring NT Kernel Logger releases its global lock on drop.
impl Drop for KernelSession {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}
