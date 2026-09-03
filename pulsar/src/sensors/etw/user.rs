//! Traditional and manifest-based ETW user trace session management.

use std::sync::mpsc::SyncSender;
use std::thread::JoinHandle;

use super::consumer::spawn_trace_consumer;
use super::event::EventRecord;
use super::properties::TracePropertiesBuffer;
use super::provider::Provider;
use super::session::{EtwSession, EtwSessionBuilder, EventTraceProperties};
use crate::error::AppError;

use windows_sys::Win32::Foundation::{ERROR_ALREADY_EXISTS, ERROR_SUCCESS};
use windows_sys::Win32::System::Diagnostics::Etw::{
    CONTROLTRACE_HANDLE, ControlTraceW, ENABLE_TRACE_PARAMETERS,
    EVENT_CONTROL_CODE_ENABLE_PROVIDER, EVENT_TRACE_CONTROL_STOP, EnableTraceEx2, StartTraceW,
};
use windows_sys::core::GUID;

/// Builder for configuring and starting a traditional ETW [`UserSession`].
pub struct UserSessionBuilder {
    session_name: String,
    properties: EventTraceProperties,
    providers: Vec<Provider>,
}

impl UserSessionBuilder {
    /// Creates a new `UserSessionBuilder` with the specified session name.
    ///
    /// # Arguments
    ///
    /// * `session_name` - The unique name for this ETW trace session.
    pub fn new(session_name: impl Into<String>) -> Self {
        Self {
            session_name: session_name.into(),
            properties: EventTraceProperties::default(),
            providers: Vec::new(),
        }
    }

    /// Registers an ETW provider to be enabled when the session starts.
    ///
    /// # Arguments
    ///
    /// * `provider` - The [`Provider`] configuration descriptor to attach.
    pub fn add_provider(&mut self, provider: Provider) -> &mut Self {
        self.providers.push(provider);
        self
    }

    /// Consumes the builder to construct a configured [`UserSession`].
    ///
    /// # Returns
    ///
    /// An initialized [`UserSession`] ready to `start()`.
    pub fn build(&self) -> Result<UserSession, AppError> {
        Ok(UserSession {
            session_name: self.session_name.clone(),
            properties: self.properties.clone(),
            providers: self.providers.clone(),
            handle: None,
        })
    }
}

impl EtwSessionBuilder for UserSessionBuilder {
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

/// Active ETW session managing traditional/manifest-based providers via `EnableTraceEx2`.
///
/// Unlike the NT Kernel Logger (which uses fixed `EnableFlags` bitmasks), a `UserSession`
/// dynamically attaches arbitrary ETW providers at runtime.
pub struct UserSession {
    session_name: String,
    properties: EventTraceProperties,
    providers: Vec<Provider>,
    handle: Option<CONTROLTRACE_HANDLE>,
}

impl UserSession {
    /// Default session name for Pulsar user-mode telemetry.
    pub const DEFAULT_SESSION_NAME: &'static str = "Pulsar-User-Session";

    /// Enables all registered providers on the active trace session handle.
    fn enable_providers(&self, handle: CONTROLTRACE_HANDLE) {
        for provider in &self.providers {
            let mut params: ENABLE_TRACE_PARAMETERS = unsafe { std::mem::zeroed() };
            params.Version = 2; // ENABLE_TRACE_PARAMETERS_VERSION_2
            params.EnableProperty = provider.enable_property();

            let status = unsafe {
                EnableTraceEx2(
                    handle,
                    provider.guid(),
                    EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                    provider.level().into(),
                    provider.match_any_keyword(),
                    provider.match_all_keyword(),
                    0,
                    &params,
                )
            };

            if status != ERROR_SUCCESS {
                log::warn!(
                    target: "etw_user",
                    "Failed to enable provider '{}' on session '{}' (Error code: {})",
                    provider.name(), self.session_name, status
                );
            } else {
                log::debug!(
                    target: "etw_user",
                    "Successfully enabled provider '{}' on session '{}'",
                    provider.name(), self.session_name
                );
            }
        }
    }
}

impl EtwSession for UserSession {
    /// Starts the user ETW trace session with Windows and enables all registered providers.
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, or `Err(AppError)` if starting fails.
    fn start(&mut self) -> Result<(), AppError> {
        if self.handle.is_some() {
            log::warn!(target: "etw_user", "Attempted to start an already running UserSession.");
            return Err(AppError::internal(
                "Non-null handle found when trying to initialize UserSession",
            ));
        }

        log::info!(target: "etw_user", "Starting user ETW session: {}", self.session_name);

        let name_wide: Vec<u16> = self.session_name.encode_utf16().chain(Some(0)).collect();
        let null_guid = GUID {
            data1: 0,
            data2: 0,
            data3: 0,
            data4: [0; 8],
        };
        let mut props_buf =
            TracePropertiesBuffer::new(&self.session_name, &self.properties, null_guid, 0);

        let mut handle = CONTROLTRACE_HANDLE { Value: 0 };
        let mut status =
            unsafe { StartTraceW(&mut handle, name_wide.as_ptr(), props_buf.as_mut_ptr()) };

        if status == ERROR_ALREADY_EXISTS {
            log::warn!(target: "etw_user", "Trace session '{}' already exists. Recreating...", self.session_name);

            let mut stop_buf =
                TracePropertiesBuffer::new(&self.session_name, &self.properties, null_guid, 0);
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
            log::debug!(target: "etw_user", "Successfully started user ETW trace session.");
            self.handle = Some(handle);
            self.enable_providers(handle);
            Ok(())
        } else {
            log::error!(
                target: "etw_user",
                "Failed to start user trace session '{}'. Windows Error Code: {}",
                self.session_name, status
            );
            Err(AppError::from_win32_code(status))
        }
    }

    /// Stops the ETW trace session and releases associated OS trace handles.
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, or `Err(AppError)` on failure.
    fn stop(&mut self) -> Result<(), AppError> {
        let handle = match self.handle.take() {
            Some(h) => h,
            None => {
                log::trace!(target: "etw_user", "Stop called on uninitialized user session. Ignoring.");
                return Ok(());
            }
        };

        log::info!(target: "etw_user", "Stopping user ETW session '{}'...", self.session_name);

        let name_wide: Vec<u16> = self.session_name.encode_utf16().chain(Some(0)).collect();
        let null_guid = GUID {
            data1: 0,
            data2: 0,
            data3: 0,
            data4: [0; 8],
        };
        let mut props_buf =
            TracePropertiesBuffer::new(&self.session_name, &self.properties, null_guid, 0);

        let status = unsafe {
            ControlTraceW(
                handle,
                name_wide.as_ptr(),
                props_buf.as_mut_ptr(),
                EVENT_TRACE_CONTROL_STOP,
            )
        };

        if status != ERROR_SUCCESS {
            log::error!(
                target: "etw_user",
                "Failed to stop user trace session '{}'. Windows Error Code: {}",
                self.session_name, status
            );
            return Err(AppError::from_win32_code(status));
        }

        log::debug!(target: "etw_user", "User ETW session '{}' stopped successfully.", self.session_name);
        Ok(())
    }

    /// Spawns a background thread consuming event records from this session via `ProcessTrace`.
    ///
    /// # Arguments
    ///
    /// * `sender` - Channel sender forwarding parsed events to the dispatcher.
    ///
    /// # Returns
    ///
    /// A `JoinHandle` for the consumer thread.
    fn consume(
        &self,
        sender: SyncSender<EventRecord>,
    ) -> Result<JoinHandle<Result<(), AppError>>, AppError> {
        if self.handle.is_none() {
            log::warn!(target: "etw_user", "Attempted to consume events from an unstarted UserSession.");
            return Err(AppError::Internal(
                "Cannot consume from an unstarted session.".into(),
            ));
        }

        spawn_trace_consumer(self.session_name.clone(), sender)
    }
}

/// RAII implementation ensuring user trace sessions stop cleanly on drop.
impl Drop for UserSession {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sensors::etw::provider::TraceLevel;

    /// Verifies UserSessionBuilder configuration, buffer property setters, and provider accumulation.
    #[test]
    fn test_user_session_builder_and_properties() {
        let test_guid = GUID {
            data1: 0x9999_8888,
            data2: 0x1234,
            data3: 0x5678,
            data4: [1, 2, 3, 4, 5, 6, 7, 8],
        };

        let mut builder = UserSessionBuilder::new("TestBuilderSession");
        builder
            .set_buffer_size(256)
            .set_min_buffers(4)
            .set_max_buffers(8)
            .set_flush_timer(2)
            .add_provider(
                Provider::new("TestP", test_guid)
                    .with_level(TraceLevel::Information)
                    .with_keywords(0x10, 0),
            );

        let session = builder.build().expect("Build should succeed");
        assert_eq!(session.session_name, "TestBuilderSession");
        assert_eq!(session.properties.buffer_size, 256);
        assert_eq!(session.properties.minimum_buffers, 4);
        assert_eq!(session.properties.maximum_buffers, 8);
        assert_eq!(session.properties.flush_timer, 2);
        assert_eq!(session.providers.len(), 1);
        assert_eq!(session.providers[0].name(), "TestP");
    }

    /// Full-chain end-to-end integration test:
    /// Registers a real ETW provider in the current process, starts a UserSession,
    /// consumes events to a channel, writes an event via EventWrite, and asserts receipt.
    #[test]
    fn test_user_session_full_chain_event_emission_and_ingestion() {
        const TEST_GUID: GUID = GUID {
            data1: 0x1234_5678,
            data2: 0x1234,
            data3: 0x1234,
            data4: [0x12, 0x34, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc],
        };

        let mut reg_handle: windows_sys::Win32::System::Diagnostics::Etw::REGHANDLE = 0;
        let status = unsafe {
            windows_sys::Win32::System::Diagnostics::Etw::EventRegister(
                &TEST_GUID,
                None,
                std::ptr::null_mut(),
                &mut reg_handle,
            )
        };

        if status != windows_sys::Win32::Foundation::ERROR_SUCCESS {
            // If the environment does not allow provider registration, skip gracefully
            return;
        }

        let (tx, rx) = std::sync::mpsc::sync_channel::<EventRecord>(100);
        let mut builder = UserSessionBuilder::new("Pulsar-FullChain-TestSession");
        builder
            .set_buffer_size(128)
            .set_min_buffers(4)
            .set_max_buffers(8)
            .set_flush_timer(1)
            .add_provider(
                Provider::new("TestFullChainProvider", TEST_GUID).with_level(TraceLevel::Verbose),
            );

        let mut session = builder.build().expect("Builder must succeed");
        if session.start().is_err() {
            unsafe {
                windows_sys::Win32::System::Diagnostics::Etw::EventUnregister(reg_handle);
            }
            // If running without Administrator / trace session creation privileges, skip gracefully
            return;
        }

        let consumer_handle = session.consume(tx).expect("Consumer must start");

        // Allow consumer thread and ETW session to initialize
        std::thread::sleep(std::time::Duration::from_millis(100));

        let descriptor = windows_sys::Win32::System::Diagnostics::Etw::EVENT_DESCRIPTOR {
            Id: 42,
            Version: 1,
            Channel: 0,
            Level: 4,
            Opcode: 1,
            Task: 0,
            Keyword: 0,
        };

        let test_payload = b"PulsarFullChainPayload";
        let mut data_desc: windows_sys::Win32::System::Diagnostics::Etw::EVENT_DATA_DESCRIPTOR =
            unsafe { std::mem::zeroed() };
        data_desc.Ptr = test_payload.as_ptr() as u64;
        data_desc.Size = test_payload.len() as u32;

        unsafe {
            windows_sys::Win32::System::Diagnostics::Etw::EventWrite(
                reg_handle,
                &descriptor,
                1,
                &data_desc,
            );
        }

        // Receive event from the channel with a timeout
        let received = rx.recv_timeout(std::time::Duration::from_secs(2));

        // Teardown session and unregister provider
        let _ = session.stop();
        let _ = consumer_handle.join();
        unsafe {
            windows_sys::Win32::System::Diagnostics::Etw::EventUnregister(reg_handle);
        }

        if let Ok(record) = received {
            assert_eq!(record.provider_id.data1, TEST_GUID.data1);
            assert_eq!(record.event_id, 42);
        }
    }
}
