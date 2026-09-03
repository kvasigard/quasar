//! Strongly-typed ETW provider configuration descriptors and severity levels.

use std::fmt;
use windows_sys::core::GUID;
use windows_sys::Win32::System::Diagnostics::Etw::EVENT_ENABLE_PROPERTY_STACK_TRACE;

use crate::helpers::format_guid;

/// Standard ETW trace logging severity levels.
///
/// Reference: <https://learn.microsoft.com/en-us/windows/win32/etw/trace-level>
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TraceLevel {
    /// Abnormal exit or termination events.
    Critical = 1,
    /// Severe errors that inhibit execution.
    Error = 2,
    /// Warnings or abnormal conditions.
    Warning = 3,
    /// Standard informational operational telemetry.
    #[default]
    Information = 4,
    /// Highly verbose debugging telemetry.
    Verbose = 5,
}

impl From<TraceLevel> for u8 {
    fn from(level: TraceLevel) -> Self {
        level as u8
    }
}

/// Strongly-typed configuration descriptor for an ETW provider.
///
/// Encapsulates the provider GUID, logging level, keyword bitmasks, and extended
/// parameters (such as inline stack tracing) passed to `EnableTraceEx2`.
#[derive(Clone)]
pub struct Provider {
    name: String,
    guid: GUID,
    level: TraceLevel,
    match_any_keyword: u64,
    match_all_keyword: u64,
    enable_property: u32,
}

impl fmt::Debug for Provider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Provider")
            .field("name", &self.name)
            .field("guid", &format_guid(&self.guid))
            .field("level", &self.level)
            .field("match_any_keyword", &format_args!("{:#x}", self.match_any_keyword))
            .field("match_all_keyword", &format_args!("{:#x}", self.match_all_keyword))
            .field("enable_property", &format_args!("{:#x}", self.enable_property))
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
    }
}

impl Eq for Provider {}

impl Provider {
    /// Creates a new `Provider` descriptor with default `Information` level and no keyword filters.
    ///
    /// # Arguments
    ///
    /// * `name` - Human-readable identifier for the provider (for diagnostics/logging).
    /// * `guid` - The unique ETW Provider GUID.
    ///
    /// # Returns
    ///
    /// An initialized `Provider` builder ready for chaining.
    pub fn new(name: impl Into<String>, guid: GUID) -> Self {
        Self {
            name: name.into(),
            guid,
            level: TraceLevel::Information,
            match_any_keyword: 0,
            match_all_keyword: 0,
            enable_property: 0,
        }
    }

    /// Sets the logging severity level threshold for this provider.
    ///
    /// # Arguments
    ///
    /// * `level` - The desired [`TraceLevel`].
    pub fn with_level(mut self, level: TraceLevel) -> Self {
        self.level = level;
        self
    }

    /// Sets the 64-bit keyword bitmasks used by ETW for category filtering.
    ///
    /// # Arguments
    ///
    /// * `match_any` - Bitmask of keywords where matching at least one bit enables the event.
    /// * `match_all` - Bitmask of keywords where all specified bits must match.
    pub fn with_keywords(mut self, match_any: u64, match_all: u64) -> Self {
        self.match_any_keyword = match_any;
        self.match_all_keyword = match_all;
        self
    }

    /// Requests that Windows capture call stack traces inline in `ExtendedData` for events emitted by this provider.
    ///
    /// Sets the `EVENT_ENABLE_PROPERTY_STACK_TRACE` flag in `ENABLE_TRACE_PARAMETERS`.
    pub fn with_stack_tracing(mut self) -> Self {
        self.enable_property |= EVENT_ENABLE_PROPERTY_STACK_TRACE;
        self
    }

    /// Adds a raw Win32 `EVENT_ENABLE_PROPERTY_*` bitmask flag (e.g. `EVENT_ENABLE_PROPERTY_IGNORE_KEYWORD_0`).
    ///
    /// # Arguments
    ///
    /// * `property` - Win32 enable property flag bitmask.
    pub fn with_property(mut self, property: u32) -> Self {
        self.enable_property |= property;
        self
    }

    /// Returns the human-readable name of the provider.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the GUID of the provider.
    pub fn guid(&self) -> &GUID {
        &self.guid
    }

    /// Returns the logging severity level.
    pub fn level(&self) -> TraceLevel {
        self.level
    }

    /// Returns the `MatchAnyKeyword` bitmask.
    pub fn match_any_keyword(&self) -> u64 {
        self.match_any_keyword
    }

    /// Returns the `MatchAllKeyword` bitmask.
    pub fn match_all_keyword(&self) -> u64 {
        self.match_all_keyword
    }

    /// Returns the `EnableProperty` bitmask.
    pub fn enable_property(&self) -> u32 {
        self.enable_property
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verifies provider configuration builder methods, keyword bitmasks, and stack tracing flags.
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
            .with_stack_tracing();

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
    }
}
