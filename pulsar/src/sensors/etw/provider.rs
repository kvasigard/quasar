//! Strongly-typed ETW provider configuration descriptors, severity levels, and kernel filters.
//!
//! [`Provider`] encapsulates all parameters passed to `EnableTraceEx2` when attaching a
//! manifest-based, TraceLogging, or PPL (Protected Process Light) provider such as
//! `Microsoft-Windows-Threat-Intelligence` to a [`UserSession`](super::UserSession).

use std::fmt;
use windows_sys::Win32::System::Diagnostics::Etw::EVENT_ENABLE_PROPERTY_STACK_TRACE;
use windows_sys::core::GUID;

use crate::helpers::format_guid;
use crate::sensors::etw::filter::ProviderFilter;

/// Standard ETW trace logging severity levels passed to `EnableTraceEx2`.
///
/// In ETW, enabling a provider at a given `TraceLevel` enables all events with a severity
/// numerical value less than or equal to that level (e.g., `Information` (`4`) captures
/// `Critical` (`1`), `Error` (`2`), `Warning` (`3`), and `Information` (`4`)).
///
/// Reference: <https://learn.microsoft.com/en-us/windows/win32/etw/trace-level>
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TraceLevel {
    /// Abnormal exit or fatal termination events (`TRACE_LEVEL_CRITICAL = 1`).
    Critical = 1,
    /// Severe error conditions (`TRACE_LEVEL_ERROR = 2`).
    Error = 2,
    /// Warnings or non-fatal abnormal conditions (`TRACE_LEVEL_WARNING = 3`).
    Warning = 3,
    /// Standard informational operational telemetry (`TRACE_LEVEL_INFORMATION = 4`).
    #[default]
    Information = 4,
    /// Detailed diagnostic and debugging telemetry (`TRACE_LEVEL_VERBOSE = 5`).
    Verbose = 5,
}

impl From<TraceLevel> for u8 {
    fn from(level: TraceLevel) -> Self {
        level as u8
    }
}

/// Strongly-typed configuration descriptor for an ETW provider enabled on a [`UserSession`](super::UserSession).
///
/// Encapsulates the provider GUID, severity threshold ([`TraceLevel`]), 64-bit `MatchAnyKeyword`
/// and `MatchAllKeyword` bitmasks, `ENABLE_TRACE_PARAMETERS.EnableProperty` flags (such as
/// inline call stack capture), and kernel-side [`ProviderFilter`] rules.
#[derive(Clone)]
pub struct Provider {
    /// Human-readable provider name used in structured logs and diagnostics.
    name: String,
    /// Unique 128-bit ETW provider GUID.
    guid: GUID,
    /// Maximum severity level threshold enabled for this provider.
    level: TraceLevel,
    /// 64-bit keyword bitmask where an event matches if *any* bit overlaps (or `0` for all).
    match_any_keyword: u64,
    /// 64-bit keyword bitmask where an event must contain *all* specified bits.
    match_all_keyword: u64,
    /// Bitmask of `EVENT_ENABLE_PROPERTY_*` flags (e.g., `EVENT_ENABLE_PROPERTY_STACK_TRACE`).
    enable_property: u32,
    /// Kernel-side `EVENT_FILTER_DESCRIPTOR` rules (Event IDs, StackWalk Event IDs, PIDs).
    filter: ProviderFilter,
}

impl fmt::Debug for Provider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Provider")
            .field("name", &self.name)
            .field("guid", &format_guid(&self.guid))
            .field("level", &self.level)
            .field(
                "match_any_keyword",
                &format_args!("{:#x}", self.match_any_keyword),
            )
            .field(
                "match_all_keyword",
                &format_args!("{:#x}", self.match_all_keyword),
            )
            .field(
                "enable_property",
                &format_args!("{:#x}", self.enable_property),
            )
            .field("filter", &self.filter)
            .finish()
    }
}

impl PartialEq for Provider {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
            && self.guid.data1 == other.guid.data1
            && self.guid.data2 == other.guid.data2
            && self.guid.data3 == other.guid.data3
            && self.guid.data4 == other.guid.data4
            && self.level == other.level
            && self.match_any_keyword == other.match_any_keyword
            && self.match_all_keyword == other.match_all_keyword
            && self.enable_property == other.enable_property
            && self.filter == other.filter
    }
}

impl Eq for Provider {}

impl Provider {
    /// Creates a new [`Provider`] descriptor with [`TraceLevel::Information`] and no keyword or Event ID filters.
    ///
    /// # Arguments
    ///
    /// * `name` - Human-readable identifier for the provider (for diagnostics/logging).
    /// * `guid` - The unique 128-bit ETW Provider GUID.
    ///
    /// # Returns
    ///
    /// An initialized [`Provider`] builder ready for method chaining.
    pub fn new(name: impl Into<String>, guid: GUID) -> Self {
        Self {
            name: name.into(),
            guid,
            level: TraceLevel::Information,
            match_any_keyword: 0,
            match_all_keyword: 0,
            enable_property: 0,
            filter: ProviderFilter::default(),
        }
    }

    /// Sets the logging severity level threshold for this provider.
    pub fn with_level(mut self, level: TraceLevel) -> Self {
        self.level = level;
        self
    }

    /// Sets the 64-bit `MatchAnyKeyword` and `MatchAllKeyword` bitmasks used by ETW for category filtering.
    pub fn with_keywords(mut self, match_any: u64, match_all: u64) -> Self {
        self.match_any_keyword = match_any;
        self.match_all_keyword = match_all;
        self
    }

    /// Requests that Windows capture call stack traces inline in `ExtendedData` (`STACK_TRACE64` / `STACK_TRACE32`)
    /// for events emitted by this provider.
    ///
    /// Sets `EVENT_ENABLE_PROPERTY_STACK_TRACE` in `ENABLE_TRACE_PARAMETERS.EnableProperty`.
    pub fn with_stack_tracing(mut self) -> Self {
        self.enable_property |= EVENT_ENABLE_PROPERTY_STACK_TRACE;
        self
    }

    /// Adds a raw Win32 `EVENT_ENABLE_PROPERTY_*` bitmask flag (e.g., `EVENT_ENABLE_PROPERTY_PROCESS_START_KEY`).
    pub fn with_property(mut self, property: u32) -> Self {
        self.enable_property |= property;
        self
    }

    /// Replaces the kernel-level [`ProviderFilter`] (`EVENT_FILTER_DESCRIPTOR`) attached to this provider.
    pub fn with_filter(mut self, filter: ProviderFilter) -> Self {
        self.filter = filter;
        self
    }

    /// Configures a kernel-level inclusive Event ID filter (`EVENT_FILTER_TYPE_EVENT_ID`) so the kernel
    /// only emits the specified Event IDs for this provider.
    pub fn include_event_ids(mut self, ids: impl IntoIterator<Item = u16>) -> Self {
        self.filter = self.filter.include_event_ids(ids);
        self
    }

    /// Configures a kernel-level exclusive Event ID filter (`EVENT_FILTER_TYPE_EVENT_ID`) so the kernel
    /// suppresses the specified Event IDs for this provider.
    pub fn exclude_event_ids(mut self, ids: impl IntoIterator<Item = u16>) -> Self {
        self.filter = self.filter.exclude_event_ids(ids);
        self
    }

    /// Enables inline stack tracing (`EVENT_ENABLE_PROPERTY_STACK_TRACE`) and restricts stack capture
    /// in the kernel (`EVENT_FILTER_TYPE_STACKWALK`) to only the specified Event IDs.
    pub fn include_stackwalk_event_ids(mut self, ids: impl IntoIterator<Item = u16>) -> Self {
        self.enable_property |= EVENT_ENABLE_PROPERTY_STACK_TRACE;
        self.filter = self.filter.include_stackwalk_event_ids(ids);
        self
    }

    /// Restricts this provider in the kernel (`EVENT_FILTER_TYPE_PID`) to the specified Process IDs (up to 8 PIDs).
    pub fn with_pids(mut self, pids: impl IntoIterator<Item = u32>) -> Self {
        self.filter = self.filter.with_pids(pids);
        self
    }

    /// Returns the human-readable name of the provider.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the 128-bit GUID of the provider.
    pub fn guid(&self) -> &GUID {
        &self.guid
    }

    /// Returns the configured [`TraceLevel`] severity threshold.
    pub fn level(&self) -> TraceLevel {
        self.level
    }

    /// Returns the 64-bit `MatchAnyKeyword` bitmask.
    pub fn match_any_keyword(&self) -> u64 {
        self.match_any_keyword
    }

    /// Returns the 64-bit `MatchAllKeyword` bitmask.
    pub fn match_all_keyword(&self) -> u64 {
        self.match_all_keyword
    }

    /// Returns the `ENABLE_TRACE_PARAMETERS.EnableProperty` bitmask.
    pub fn enable_property(&self) -> u32 {
        self.enable_property
    }

    /// Returns a reference to the kernel-level [`ProviderFilter`] attached to this provider.
    pub fn filter(&self) -> &ProviderFilter {
        &self.filter
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verifies provider configuration builder methods, keyword bitmasks, stack tracing flags, and kernel filters.
    #[test]
    fn test_provider_builder_and_flags() {
        let test_guid = GUID {
            data1: 0xAAAA_BBBB,
            data2: 0x1111,
            data3: 0x2222,
            data4: [1, 2, 3, 4, 5, 6, 7, 8],
        };

        let provider = Provider::new("TestProvider", test_guid)
            .with_level(TraceLevel::Verbose)
            .with_keywords(0x0000_0001, 0x0000_0002)
            .include_event_ids([1, 2, 3])
            .include_stackwalk_event_ids([1]);

        assert_eq!(provider.name(), "TestProvider");
        assert_eq!(provider.guid().data1, 0xAAAA_BBBB);
        assert_eq!(provider.level(), TraceLevel::Verbose);
        assert_eq!(u8::from(provider.level()), 5);
        assert_eq!(provider.match_any_keyword(), 0x0000_0001);
        assert_eq!(provider.match_all_keyword(), 0x0000_0002);
        assert_ne!(
            provider.enable_property() & EVENT_ENABLE_PROPERTY_STACK_TRACE,
            0
        );
        assert!(!provider.filter().is_empty());
    }
}
