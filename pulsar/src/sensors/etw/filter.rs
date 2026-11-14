//! Kernel-side provider filtering (`EVENT_FILTER_DESCRIPTOR`) for `EnableTraceEx2`.
//!
//! Allows manifest and TraceLogging ETW providers (such as `Microsoft-Windows-Threat-Intelligence`
//! or `Microsoft-Windows-Kernel-Process`) to filter events by Event ID, capture stack traces only
//! for specific Event IDs, or scope telemetry to specific Process IDs directly inside the Windows
//! kernel before events are written to the trace buffer.

use windows_sys::Win32::System::Diagnostics::Etw::{
    EVENT_FILTER_DESCRIPTOR, EVENT_FILTER_TYPE_EVENT_ID, EVENT_FILTER_TYPE_PID,
    EVENT_FILTER_TYPE_STACKWALK, MAX_EVENT_FILTER_EVENT_ID_COUNT, MAX_EVENT_FILTER_PID_COUNT,
};

/// Filter rule specifying a list of 16-bit Event IDs to either include (`filter_in = true`)
/// or exclude (`filter_in = false`) in the kernel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventIdFilter {
    /// When `true`, only the listed Event IDs are emitted. When `false`, all Event IDs *except*
    /// the listed ones are emitted.
    pub filter_in: bool,
    /// List of 16-bit Event IDs (capped at `MAX_EVENT_FILTER_EVENT_ID_COUNT` = 64 by Windows).
    pub ids: Vec<u16>,
}

impl EventIdFilter {
    /// Creates an inclusive filter that only allows the specified Event IDs.
    pub fn include(ids: impl IntoIterator<Item = u16>) -> Self {
        let mut vec: Vec<u16> = ids
            .into_iter()
            .take(MAX_EVENT_FILTER_EVENT_ID_COUNT as usize)
            .collect();
        vec.sort_unstable();
        vec.dedup();
        Self {
            filter_in: true,
            ids: vec,
        }
    }

    /// Creates an exclusive filter that suppresses the specified Event IDs.
    pub fn exclude(ids: impl IntoIterator<Item = u16>) -> Self {
        let mut vec: Vec<u16> = ids
            .into_iter()
            .take(MAX_EVENT_FILTER_EVENT_ID_COUNT as usize)
            .collect();
        vec.sort_unstable();
        vec.dedup();
        Self {
            filter_in: false,
            ids: vec,
        }
    }

    /// Serializes this filter into the binary layout of Win32 `EVENT_FILTER_EVENT_ID`.
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let count = self.ids.len().min(MAX_EVENT_FILTER_EVENT_ID_COUNT as usize);
        let mut buf = Vec::with_capacity(4 + count * 2);
        buf.push(u8::from(self.filter_in)); // FilterIn: BOOLEAN
        buf.push(0); // Reserved: UCHAR
        buf.extend_from_slice(&(count as u16).to_ne_bytes()); // Count: USHORT
        for &id in &self.ids[..count] {
            buf.extend_from_slice(&id.to_ne_bytes());
        }
        buf
    }
}

/// Kernel-side filter configuration attached to a [`Provider`](super::provider::Provider).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProviderFilter {
    /// Optional kernel-side Event ID filter (`EVENT_FILTER_TYPE_EVENT_ID`).
    pub event_ids: Option<EventIdFilter>,
    /// Optional kernel-side StackWalk Event ID filter (`EVENT_FILTER_TYPE_STACKWALK`).
    pub stackwalk_event_ids: Option<EventIdFilter>,
    /// Optional list of Process IDs to scope the provider to (`EVENT_FILTER_TYPE_PID`, max 8).
    pub pids: Vec<u32>,
}

impl ProviderFilter {
    /// Creates an empty [`ProviderFilter`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Restricts the provider in the kernel to only emit the specified Event IDs.
    pub fn include_event_ids(mut self, ids: impl IntoIterator<Item = u16>) -> Self {
        self.event_ids = Some(EventIdFilter::include(ids));
        self
    }

    /// Instructs the kernel to suppress the specified Event IDs for this provider.
    pub fn exclude_event_ids(mut self, ids: impl IntoIterator<Item = u16>) -> Self {
        self.event_ids = Some(EventIdFilter::exclude(ids));
        self
    }

    /// Instructs the kernel to capture inline stack traces (`EVENT_FILTER_TYPE_STACKWALK`)
    /// only for the specified Event IDs.
    pub fn include_stackwalk_event_ids(mut self, ids: impl IntoIterator<Item = u16>) -> Self {
        self.stackwalk_event_ids = Some(EventIdFilter::include(ids));
        self
    }

    /// Restricts the provider to events originating from the specified Process IDs (up to 8 PIDs).
    pub fn with_pids(mut self, pids: impl IntoIterator<Item = u32>) -> Self {
        self.pids = pids
            .into_iter()
            .take(MAX_EVENT_FILTER_PID_COUNT as usize)
            .collect();
        self
    }

    /// Returns `true` if no kernel-side filters are configured.
    pub fn is_empty(&self) -> bool {
        self.event_ids.as_ref().is_none_or(|f| f.ids.is_empty())
            && self
                .stackwalk_event_ids
                .as_ref()
                .is_none_or(|f| f.ids.is_empty())
            && self.pids.is_empty()
    }

    /// Materializes pinned backing buffers and an `[EVENT_FILTER_DESCRIPTOR]` array ready for `EnableTraceEx2`.
    pub(crate) fn build_descriptors(&self) -> BuiltFilterDescriptors {
        let mut buffers: Vec<Box<[u8]>> = Vec::with_capacity(3);
        let mut descriptors: Vec<EVENT_FILTER_DESCRIPTOR> = Vec::with_capacity(3);

        if let Some(ref evt_filter) = self.event_ids
            && !evt_filter.ids.is_empty()
        {
            let boxed = evt_filter.to_bytes().into_boxed_slice();
            descriptors.push(EVENT_FILTER_DESCRIPTOR {
                Ptr: boxed.as_ptr() as usize as u64,
                Size: boxed.len() as u32,
                Type: EVENT_FILTER_TYPE_EVENT_ID,
            });
            buffers.push(boxed);
        }

        if let Some(ref sw_filter) = self.stackwalk_event_ids
            && !sw_filter.ids.is_empty()
        {
            let boxed = sw_filter.to_bytes().into_boxed_slice();
            descriptors.push(EVENT_FILTER_DESCRIPTOR {
                Ptr: boxed.as_ptr() as usize as u64,
                Size: boxed.len() as u32,
                Type: EVENT_FILTER_TYPE_STACKWALK,
            });
            buffers.push(boxed);
        }

        if !self.pids.is_empty() {
            let count = self.pids.len().min(MAX_EVENT_FILTER_PID_COUNT as usize);
            let mut pid_bytes = Vec::with_capacity(count * 4);
            for &pid in &self.pids[..count] {
                pid_bytes.extend_from_slice(&pid.to_ne_bytes());
            }
            let boxed = pid_bytes.into_boxed_slice();
            descriptors.push(EVENT_FILTER_DESCRIPTOR {
                Ptr: boxed.as_ptr() as usize as u64,
                Size: boxed.len() as u32,
                Type: EVENT_FILTER_TYPE_PID,
            });
            buffers.push(boxed);
        }

        BuiltFilterDescriptors {
            _buffers: buffers,
            descriptors,
        }
    }
}

/// Owns the heap-pinned filter payload buffers alongside the [`EVENT_FILTER_DESCRIPTOR`] array
/// passed to `EnableTraceEx2`.
pub(crate) struct BuiltFilterDescriptors {
    _buffers: Vec<Box<[u8]>>,
    descriptors: Vec<EVENT_FILTER_DESCRIPTOR>,
}

impl BuiltFilterDescriptors {
    #[inline]
    pub fn as_slice(&self) -> &[EVENT_FILTER_DESCRIPTOR] {
        &self.descriptors
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_filter_binary_layout_and_descriptors() {
        let filter = ProviderFilter::new()
            .include_event_ids([10, 1, 5, 10]) // Deduped and sorted -> [1, 5, 10]
            .include_stackwalk_event_ids([1, 5])
            .with_pids([1234, 5678]);

        assert!(!filter.is_empty());
        let built = filter.build_descriptors();
        let descs = built.as_slice();
        assert_eq!(descs.len(), 3);

        // 1. EVENT_FILTER_TYPE_EVENT_ID: 4-byte header + 3 * 2 bytes = 10 bytes
        assert_eq!(descs[0].Type, EVENT_FILTER_TYPE_EVENT_ID);
        assert_eq!(descs[0].Size, 10);
        let raw_evt =
            unsafe { std::slice::from_raw_parts(descs[0].Ptr as usize as *const u8, 10) };
        assert_eq!(raw_evt[0], 1); // FilterIn = true
        assert_eq!(u16::from_ne_bytes([raw_evt[2], raw_evt[3]]), 3); // Count = 3
        assert_eq!(u16::from_ne_bytes([raw_evt[4], raw_evt[5]]), 1);
        assert_eq!(u16::from_ne_bytes([raw_evt[6], raw_evt[7]]), 5);
        assert_eq!(u16::from_ne_bytes([raw_evt[8], raw_evt[9]]), 10);

        // 2. EVENT_FILTER_TYPE_STACKWALK: 4-byte header + 2 * 2 bytes = 8 bytes
        assert_eq!(descs[1].Type, EVENT_FILTER_TYPE_STACKWALK);
        assert_eq!(descs[1].Size, 8);

        // 3. EVENT_FILTER_TYPE_PID: 2 * 4 bytes = 8 bytes
        assert_eq!(descs[2].Type, EVENT_FILTER_TYPE_PID);
        assert_eq!(descs[2].Size, 8);
    }
}
