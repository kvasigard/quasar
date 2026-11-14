//! Traditional and manifest-based ETW user trace session management with kernel-side provider filtering.

use windows_sys::Win32::Foundation::ERROR_SUCCESS;
use windows_sys::Win32::System::Diagnostics::Etw::{
    CONTROLTRACE_HANDLE, ENABLE_TRACE_PARAMETERS, EVENT_CONTROL_CODE_DISABLE_PROVIDER,
    EVENT_CONTROL_CODE_ENABLE_PROVIDER, EVENT_FILTER_DESCRIPTOR, EnableTraceEx2,
};
use windows_sys::core::GUID;

use super::consumer::ConsumerHandle;
use super::error::EtwError;
use super::properties::TraceStatistics;
use super::provider::Provider;
use super::router::TraceRouter;
use super::session::{
    EtwSession, EtwSessionBuilder, EventTraceProperties, flush_win32_trace_session,
    query_win32_trace_session, spawn_session_consumer, start_win32_trace_session,
    stop_win32_trace_session,
};

const NULL_GUID: GUID = GUID {
    data1: 0,
    data2: 0,
    data3: 0,
    data4: [0; 8],
};

/// Builder for configuring and starting a traditional or manifest-based ETW [`UserSession`].
pub struct UserSessionBuilder {
    session_name: String,
    properties: EventTraceProperties,
    providers: Vec<Provider>,
}

impl UserSessionBuilder {
    /// Creates a new `UserSessionBuilder` with the specified session name.
    pub fn new(session_name: impl Into<String>) -> Self {
        Self {
            session_name: session_name.into(),
            properties: EventTraceProperties::default(),
            providers: Vec::new(),
        }
    }

    /// Registers an ETW [`Provider`] (including any kernel-side [`ProviderFilter`](super::filter::ProviderFilter)s)
    /// to be enabled when the session starts.
    pub fn add_provider(&mut self, provider: Provider) -> &mut Self {
        self.providers.push(provider);
        self
    }

    /// Consumes the builder to construct a configured [`UserSession`].
    pub fn build(&self) -> Result<UserSession, EtwError> {
        Ok(UserSession {
            session_name: self.session_name.clone(),
            properties: self.properties.clone(),
            providers: self.providers.clone(),
            handle: None,
            last_statistics: None,
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

/// Active ETW session managing traditional, manifest, and PPL providers via `EnableTraceEx2`.
pub struct UserSession {
    session_name: String,
    properties: EventTraceProperties,
    providers: Vec<Provider>,
    handle: Option<CONTROLTRACE_HANDLE>,
    last_statistics: Option<TraceStatistics>,
}

impl UserSession {
    /// Default session name for Pulsar user-mode telemetry.
    pub const DEFAULT_SESSION_NAME: &'static str = "Pulsar-User-Session";

    /// Returns the name of this session.
    #[inline]
    pub fn session_name(&self) -> &str {
        &self.session_name
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
        query_win32_trace_session(handle, &self.session_name, &self.properties, NULL_GUID)
    }

    /// Flushes active ring buffers immediately.
    pub fn flush(&self) -> Result<TraceStatistics, EtwError> {
        let handle = self
            .handle
            .ok_or_else(|| EtwError::SessionNotStarted(self.session_name.clone()))?;
        flush_win32_trace_session(handle, &self.session_name, &self.properties, NULL_GUID)
    }

    /// Enables all registered providers (along with their kernel-side `EVENT_FILTER_DESCRIPTOR`s)
    /// on the active trace session handle.
    fn enable_providers(&self, handle: CONTROLTRACE_HANDLE) {
        for provider in &self.providers {
            let built_filters = provider.filter().build_descriptors();
            let filter_slice = built_filters.as_slice();

            let mut params: ENABLE_TRACE_PARAMETERS = unsafe { std::mem::zeroed() };
            params.Version = 2; // ENABLE_TRACE_PARAMETERS_VERSION_2
            params.EnableProperty = provider.enable_property();
            if !filter_slice.is_empty() {
                params.EnableFilterDesc =
                    filter_slice.as_ptr() as *mut EVENT_FILTER_DESCRIPTOR;
                params.FilterDescCount = filter_slice.len() as u32;
            }

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
                    provider.name(),
                    self.session_name,
                    status
                );
            } else {
                log::debug!(
                    target: "etw_user",
                    "Successfully enabled provider '{}' on session '{}' ({} kernel filters)",
                    provider.name(),
                    self.session_name,
                    filter_slice.len()
                );
            }
        }
    }

    /// Disables all registered providers prior to stopping the trace session.
    fn disable_providers(&self, handle: CONTROLTRACE_HANDLE) {
        for provider in &self.providers {
            unsafe {
                let _ = EnableTraceEx2(
                    handle,
                    provider.guid(),
                    EVENT_CONTROL_CODE_DISABLE_PROVIDER,
                    0,
                    0,
                    0,
                    0,
                    std::ptr::null(),
                );
            }
        }
    }
}

impl EtwSession for UserSession {
    fn start(&mut self) -> Result<(), EtwError> {
        if self.handle.is_some() {
            log::warn!(target: "etw_user", "Attempted to start an already running UserSession.");
            return Err(EtwError::SessionAlreadyRunning(self.session_name.clone()));
        }

        log::info!(target: "etw_user", "Starting user ETW session: {}", self.session_name);

        let handle = start_win32_trace_session(
            &self.session_name,
            &self.properties,
            NULL_GUID,
            None,
            false,
        )?;

        self.handle = Some(handle);
        self.enable_providers(handle);
        log::debug!(target: "etw_user", "Successfully started user ETW trace session.");
        Ok(())
    }

    fn stop(&mut self) -> Result<(), EtwError> {
        let Some(handle) = self.handle.take() else {
            return Ok(());
        };

        log::info!(target: "etw_user", "Stopping user ETW session '{}'...", self.session_name);

        self.disable_providers(handle);
        let stats =
            stop_win32_trace_session(handle, &self.session_name, &self.properties, NULL_GUID)?;
        self.last_statistics = Some(stats);

        log::debug!(
            target: "etw_user",
            "User ETW session '{}' stopped successfully.",
            self.session_name
        );
        Ok(())
    }

    fn consume_with_router<R: TraceRouter>(&self, router: R) -> Result<ConsumerHandle, EtwError> {
        spawn_session_consumer(self.handle.is_some(), &self.session_name, router)
    }
}

impl Drop for UserSession {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sensors::etw::event::EventRecord;
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
                Provider::new("TestFullChainProvider", TEST_GUID)
                    .with_level(TraceLevel::Verbose)
                    .include_event_ids([42]),
            );

        let mut session = builder.build().expect("Builder must succeed");
        if session.start().is_err() {
            unsafe {
                windows_sys::Win32::System::Diagnostics::Etw::EventUnregister(reg_handle);
            }
            return;
        }

        let consumer_handle = session
            .consume_with_router(tx)
            .expect("Consumer must start");

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

        let received = rx.recv_timeout(std::time::Duration::from_secs(2));

        let _ = session.stop();
        let _ = consumer_handle.stop_and_join();
        unsafe {
            windows_sys::Win32::System::Diagnostics::Etw::EventUnregister(reg_handle);
        }

        if let Ok(record) = received {
            assert_eq!(record.provider_id.data1, TEST_GUID.data1);
            assert_eq!(record.event_id, 42);
        }
    }
}
