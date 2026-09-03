//! Background ETW trace consumer worker and C-ABI callback.

use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{SyncSender, TrySendError};
use std::thread::JoinHandle;

use super::error::EtwError;
use super::event::EventRecord;

use windows_sys::Win32::Foundation::{ERROR_SUCCESS, GetLastError};
use windows_sys::Win32::System::Diagnostics::Etw::{
    CloseTrace, EVENT_RECORD, EVENT_TRACE_LOGFILEW, OpenTraceW, PROCESS_TRACE_MODE_EVENT_RECORD,
    PROCESS_TRACE_MODE_RAW_TIMESTAMP, PROCESS_TRACE_MODE_REAL_TIME, ProcessTrace,
};

/// Context passed to the ETW C-callback function.
pub struct TraceContext {
    /// Sender channel forwarding parsed event records to the event dispatcher.
    pub sender: SyncSender<EventRecord>,
    /// Process ID of the tracer to filter out self-generated telemetry.
    pub current_pid: u32,
    /// Flag ensuring the channel saturation warning is only emitted once.
    pub channel_full_warned: AtomicBool,
}

impl TraceContext {
    /// Creates a new `TraceContext`, caching the current process ID.
    ///
    /// # Arguments
    ///
    /// * `sender` - The channel sender for event records.
    ///
    /// # Returns
    ///
    /// An initialized `TraceContext`.
    pub fn new(sender: SyncSender<EventRecord>) -> Self {
        Self {
            sender,
            current_pid: std::process::id(),
            channel_full_warned: AtomicBool::new(false),
        }
    }
}

/// The static C-ABI callback invoked synchronously by Windows via `ProcessTrace`.
///
/// # Safety
///
/// `record` must be a valid pointer to an `EVENT_RECORD` provided by the ETW runtime.
unsafe extern "system" fn etw_callback(record: *mut EVENT_RECORD) {
    if record.is_null() {
        return;
    }

    // SAFETY: Verified non-null pointer above.
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

        // Parse and send the raw EventRecord to the Dispatcher.
        if let Some(event_record) = EventRecord::from_raw(record) {
            if let Err(err) = (*ctx_ptr).sender.try_send(event_record) {
                match err {
                    TrySendError::Full(_) => {
                        // Warn only once if the channel is full
                        if !(*ctx_ptr).channel_full_warned.swap(true, Ordering::Relaxed) {
                            log::warn!(
                                target: "etw_consumer",
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
}

/// Spawns a dedicated background thread consuming event records from an active ETW session via `ProcessTrace`.
///
/// # Arguments
///
/// * `session_name` - The name of the started ETW session.
/// * `sender` - Synchronous channel sender pushing raw `EventRecord` items to the dispatcher.
///
/// # Returns
///
/// A `JoinHandle` for the consumer thread.
///
/// # Errors
///
/// Returns [`EtwError::WindowsApi`] if `OpenTraceW` fails.
pub fn spawn_trace_consumer(
    session_name: String,
    sender: SyncSender<EventRecord>,
) -> Result<JoinHandle<Result<(), EtwError>>, EtwError> {
    log::info!(target: "etw_consumer", "Spawning background event consumption thread for '{}'...", session_name);

    let handle = std::thread::spawn(move || {
        let mut name_wide: Vec<u16> = session_name.encode_utf16().chain(Some(0)).collect();
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

            if trace_handle.Value == 0xFFFF_FFFF_FFFF_FFFF || trace_handle.Value == 0 {
                let err_code = GetLastError();
                return Err(EtwError::from_win32_code(err_code));
            }

            log::debug!(target: "etw_consumer", "Blocking ProcessTrace loop started for session '{}'.", session_name);

            let status = ProcessTrace(&trace_handle, 1, std::ptr::null_mut(), std::ptr::null_mut());

            CloseTrace(trace_handle);

            if status != ERROR_SUCCESS {
                return Err(EtwError::from_win32_code(status));
            }
        }

        log::info!(target: "etw_consumer", "ETW consumer thread for '{}' exited gracefully.", session_name);
        Ok(())
    });

    Ok(handle)
}
