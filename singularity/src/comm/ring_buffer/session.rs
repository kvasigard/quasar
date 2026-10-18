//! Active user-mode mapping session spanning all per-CPU partitions.

use shared::ioctl::PerCpuMapResponse;
use shared::ring_buffer::{PER_CPU_DATA_SIZE, PerCpuRingHeader};

use super::mdl::MdlSection;
use super::notifier::KernelNotificationEvent;

/// Active user-mode mapping session spanning all per-CPU partitions.
///
/// Encapsulates the user-mode virtual memory projections for both the data
/// and status partitions, alongside an optional kernel notification event.
/// When dropped (e.g. during `device_file_cleanup`), the RAII destructors
/// unmap locked pages and dereference the kernel event while the target process
/// page tables are still intact.
pub struct UserModeMemory {
    pub(crate) data_section: MdlSection,
    pub(crate) status_section: MdlSection,
    pub(crate) notification_event: Option<KernelNotificationEvent>,
    pub(crate) cpu_count: u32,
    pub(crate) file_object: usize,
    pub(crate) owner_process: usize,
}

unsafe impl Send for UserModeMemory {}

impl UserModeMemory {
    /// Constructs a new active user-mode mapping session bound to the originating file object and process.
    ///
    /// Stores mapped MDL sections alongside host processor geometry and ownership identifiers.
    ///
    /// # Arguments
    ///
    /// * `data_section` - Mapped user-mode data section.
    /// * `status_section` - Mapped user-mode status section.
    /// * `cpu_count` - Number of active logical processor partitions.
    /// * `file_object` - Originating `WDFFILEOBJECT` identifier.
    /// * `owner_process` - Originating `PEPROCESS` identifier.
    ///
    /// # Return values
    ///
    /// * `Self` - Initialized user-mode mapping session.
    pub(crate) fn new(
        data_section: MdlSection,
        status_section: MdlSection,
        cpu_count: u32,
        file_object: usize,
        owner_process: usize,
    ) -> Self {
        Self {
            data_section,
            status_section,
            notification_event: None,
            cpu_count,
            file_object,
            owner_process,
        }
    }

    /// Returns the `WDFFILEOBJECT` address that owns this user-mode mapping.
    #[inline(always)]
    pub(crate) fn file_object(&self) -> usize {
        self.file_object
    }

    /// Returns the `PEPROCESS` address of the process into which these MDL pages are mapped.
    #[inline(always)]
    pub(crate) fn owner_process(&self) -> usize {
        self.owner_process
    }

    /// Formats the mapped virtual addresses into a [`PerCpuMapResponse`] structure.
    ///
    /// Extracts 64-bit virtual memory pointers from both MDL sections to populate the IOCTL response.
    ///
    /// # Return values
    ///
    /// * `PerCpuMapResponse` - Geometry and address descriptor payload for the user-mode agent.
    pub(crate) fn response(&self) -> PerCpuMapResponse {
        PerCpuMapResponse {
            data_address: self.data_section.user_addr().as_ptr() as u64,
            status_address: self.status_section.user_addr().as_ptr() as u64,
            cpu_count: self.cpu_count,
            per_cpu_data_size: PER_CPU_DATA_SIZE as u32,
            per_cpu_status_size: core::mem::size_of::<PerCpuRingHeader>() as u32,
            _reserved: 0,
        }
    }

    /// Attaches a registered kernel notification event to this active session, returning any
    /// previously attached event so the caller can drop it outside the spinlock at `PASSIVE_LEVEL`.
    ///
    /// # Arguments
    ///
    /// * `event` - RAII wrapped kernel event object.
    ///
    /// # Return values
    ///
    /// * `Option<KernelNotificationEvent>` - Previously registered event object, if any.
    pub(crate) fn set_notification_event(
        &mut self,
        event: KernelNotificationEvent,
    ) -> Option<KernelNotificationEvent> {
        self.notification_event.replace(event)
    }

    /// Signals the user-mode reader thread to wake up.
    ///
    /// Sets the attached `KEVENT` object if one is currently registered.
    #[inline(always)]
    pub(crate) fn signal_reader(&self) {
        if let Some(ref event) = self.notification_event {
            event.set();
        }
    }
}
