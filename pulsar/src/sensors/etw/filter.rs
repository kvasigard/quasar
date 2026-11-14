//! Kernel-side provider filtering (`EVENT_FILTER_DESCRIPTOR`) for `EnableTraceEx2`.
//!
//! # Why Filter in the Kernel
//!
//! High-volume manifest providers (such as `Microsoft-Windows-Kernel-Process` or
//! `Microsoft-Windows-Threat-Intelligence`) can emit dozens of event types, many of which an
//! EDR rule engine does not need, or for which inline stack traces (`EVENT_ENABLE_PROPERTY_STACK_TRACE`)
//! are only desirable on a small subset of Event IDs.
//!
//! Passing `EVENT_FILTER_DESCRIPTOR` structures to `EnableTraceEx2` instructs the Windows
//! kernel to drop unwanted Event IDs or skip stack walks *before* writing into the ETW ring
//! buffer—saving kernel CPU time, ring-buffer memory, and user-mode callback invocations.

use windows_sys::Win32::System::Diagnostics::Etw::{
    EVENT_FILTER_DESCRIPTOR, EVENT_FILTER_TYPE_EVENT_ID, EVENT_FILTER_TYPE_PID,
    EVENT_FILTER_TYPE_STACKWALK, MAX_EVENT_FILTER_EVENT_ID_COUNT, MAX_EVENT_FILTER_PID_COUNT,
};

/// Filter rule specifying a sorted, deduplicated list of 16-bit Event IDs to either include
/// (`filter_in = true`) or exclude (`filter_in = false`) inside the Windows kernel.
///
/// Used for both `EVENT_FILTER_TYPE_EVENT_ID` (which filters event emission) and
/// `EVENT_FILTER_TYPE_STACKWALK` (which restricts inline stack walking to specific Event IDs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventIdFilter {
    /// When `true` (`FILTER_IN`), only the listed Event IDs are matched. When `false`, all
    /// Event IDs *except* the listed ones are matched.
    pub filter_in: bool,
    /// Sorted, deduplicated 16-bit Event IDs (capped at `MAX_EVENT_FILTER_EVENT_ID_COUNT = 64` by Windows).
    pub ids: Vec<u16>,
}

impl EventIdFilter {
    /// Creates an inclusive filter (`FilterIn = TRUE`) that only matches the specified Event IDs.
    ///
    /// Automatically truncates to `MAX_EVENT_FILTER_EVENT_ID_COUNT` (`64`), sorts, and deduplicates.
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

    /// Creates an exclusive filter (`FilterIn = FALSE`) that suppresses the specified Event IDs.
    ///
    /// Automatically truncates to `MAX_EVENT_FILTER_EVENT_ID_COUNT` (`64`), sorts, and deduplicates.
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

    /// Serializes this filter into the variable-length binary layout of Win32 `EVENT_FILTER_EVENT_ID`.
    ///
    /// In `evntprov.h`, `EVENT_FILTER_EVENT_ID` is defined as:
    /// - `FilterIn: BOOLEAN` (`1` byte at offset `0`)
    /// - `Reserved: UCHAR` (`1` byte at offset `1`)
    /// - `Count: USHORT` (`2` bytes at offset `2`)
    /// - `Events: USHORT[Count]` (`2 * Count` bytes starting at offset `4`)
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

/// Declarative kernel-side filter configuration attached to a [`Provider`](super::provider::Provider).
///
/// Combines optional Event ID filtering (`EVENT_FILTER_TYPE_EVENT_ID`), selective stack-walk
/// filtering (`EVENT_FILTER_TYPE_STACKWALK`), and Process ID scoping (`EVENT_FILTER_TYPE_PID`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProviderFilter {
    /// Optional kernel-side Event ID filter (`EVENT_FILTER_TYPE_EVENT_ID`).
    pub event_ids: Option<EventIdFilter>,
    /// Optional kernel-side StackWalk Event ID filter (`EVENT_FILTER_TYPE_STACKWALK`).
    pub stackwalk_event_ids: Option<EventIdFilter>,
    /// Optional list of Process IDs to scope the provider to (`EVENT_FILTER_TYPE_PID`, max 8 PIDs).
    pub pids: Vec<u32>,
}

impl ProviderFilter {
    /// Creates an empty [`ProviderFilter`] with no active kernel filters.
    pub fn new() -> Self {
        Self::default()
    }

    /// Restricts the provider in the kernel to only emit the specified Event IDs (`EVENT_FILTER_TYPE_EVENT_ID`).
    pub fn include_event_ids(mut self, ids: impl IntoIterator<Item = u16>) -> Self {
        self.event_ids = Some(EventIdFilter::include(ids));
        self
    }

    /// Instructs the kernel to suppress the specified Event IDs for this provider (`EVENT_FILTER_TYPE_EVENT_ID`).
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

    /// Restricts the provider in the kernel to events originating from the specified Process IDs
    /// (`EVENT_FILTER_TYPE_PID`, capped at `MAX_EVENT_FILTER_PID_COUNT = 8` by Windows).
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

    /// Materializes pinned heap backing buffers and a contiguous `[EVENT_FILTER_DESCRIPTOR]` array
    /// ready to be passed to `EnableTraceEx2` via `ENABLE_TRACE_PARAMETERS`.
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

/// RAII container owning the heap-pinned filter payload buffers alongside the
/// [`EVENT_FILTER_DESCRIPTOR`] array passed to `EnableTraceEx2`.
///
/// # Lifetime Invariant
///
/// Each `EVENT_FILTER_DESCRIPTOR.Ptr` stores a raw 64-bit pointer into its corresponding
/// `Box<[u8]>` in `_buffers`. Keeping `_buffers` alive inside `BuiltFilterDescriptors`
/// guarantees those pointers remain valid for the duration of the `EnableTraceEx2` call.
pub(crate) struct BuiltFilterDescriptors {
    /// Pinned byte buffers referenced by `descriptors[*].Ptr`.
    _buffers: Vec<Box<[u8]>>,
    /// Contiguous descriptor array passed to `ENABLE_TRACE_PARAMETERS.EnableFilterDesc`.
    descriptors: Vec<EVENT_FILTER_DESCRIPTOR>,
}

impl BuiltFilterDescriptors {
    /// Returns the contiguous slice of [`EVENT_FILTER_DESCRIPTOR`] items.
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
