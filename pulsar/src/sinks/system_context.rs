//! Fast ingress subscriber responsible for ingesting process and module lifecycle telemetry.

use crate::{
    context,
    pipeline::{Event, Subscriber},
};
use std::sync::Arc;

/// Opcode emitted when a new process is created (`NtCreateUserProcess` / `CreateProcess`).
///
/// Indicates that an `EPROCESS` object has been allocated by the kernel and a virtual
/// address space (CR3 directory table) has been assigned. The engine must generate
/// a new `ProcessKey`, store the initial `ProcessContext`, and link the parent-child node.
const OPCODE_PROCESS_START: u8 = 1;

/// Opcode emitted when a process terminates (`NtTerminateProcess` / `ExitProcess`).
///
/// Indicates that all threads within the process have exited or been terminated.
/// The event payload contains the final exit status code. The engine marks the internal
/// context as exited and begins the retention countdown for memory pruning.
const OPCODE_PROCESS_END: u8 = 2;

/// Data Collection Start: Initial rundown snapshot of running processes.
///
/// Emitted by the kernel trace session immediately after enabling the `EVENT_TRACE_FLAG_PROCESS`
/// mask. It enumerates all processes that were already alive before the EDR started, allowing
/// the engine to populate the tree with existing baseline state without missing active ancestry.
const OPCODE_PROCESS_DC_START: u8 = 3;

/// Data Collection End: Rundown completion marker.
///
/// Indicates that the initial active process snapshot enumeration has concluded. Any process
/// events received following this opcode represent live real-time system activity.
const OPCODE_PROCESS_DC_END: u8 = 4;

/// Opcode emitted when an executable binary or DLL is mapped into memory.
///
/// Fired when `NtMapViewOfSection` maps an image with `SEC_IMAGE` attributes.
/// Used to detect DLL side-loading, process hollowing base shifts, and injected module loads.
const OPCODE_IMAGE_LOAD: u8 = 10;

/// Opcode emitted when an image section is unmapped from a process address space.
///
/// Fired during `NtUnmapViewOfSection` or `FreeLibrary` calls.
const OPCODE_IMAGE_UNLOAD: u8 = 2;

/// Image Rundown Start: Snapshot of all loaded binaries across active processes.
///
/// Emitted during trace session initialization to catalogue all DLLs and executables
/// currently mapped in every process running on the host.
const OPCODE_IMAGE_DC_START: u8 = 3;

/// Image Rundown End: Marks the completion of the baseline image enumeration.
const OPCODE_IMAGE_DC_END: u8 = 4;

/// 32-bit prefix for the Kernel Process Provider GUID `{3d6fa8d0-fe05-11d0-9dda-00c04fd7ba7c}`.
const KERNEL_PROCESS_GUID_PREFIX: u32 = 0x3d6fa8d0;

/// 32-bit prefix for the Kernel Image Load Provider GUID `{2cb15d1d-5fc1-11d2-abe1-00a0c911f518}`.
const KERNEL_IMAGE_GUID_PREFIX: u32 = 0x2cb15d1d;

/// Fast ingress sink responsible for ingesting process and module lifecycle telemetry.
///
/// Evaluates kernel trace opcodes and updates the centralized system context tree.
pub struct SystemContextSink;

impl Subscriber for SystemContextSink {
    /// Performs an early bitwise filter to reject unrelated kernel telemetry before dispatch.
    ///
    /// # Arguments
    ///
    /// * `event` - Reference to the incoming pipeline `Event`.
    ///
    /// # Returns
    ///
    /// `true` if the event is a relevant process or image lifecycle record, `false` otherwise.
    #[inline]
    fn is_interested(&self, event: &Event) -> bool {
        let Event::Etw(record) = event;
        let prefix = record.provider_id.data1;

        let is_process = prefix == KERNEL_PROCESS_GUID_PREFIX
            && matches!(
                record.opcode,
                OPCODE_PROCESS_START
                    | OPCODE_PROCESS_END
                    | OPCODE_PROCESS_DC_START
                    | OPCODE_PROCESS_DC_END
            );

        let is_image = prefix == KERNEL_IMAGE_GUID_PREFIX
            && matches!(
                record.opcode,
                OPCODE_IMAGE_LOAD
                    | OPCODE_IMAGE_UNLOAD
                    | OPCODE_IMAGE_DC_START
                    | OPCODE_IMAGE_DC_END
            );

        is_process || is_image
    }

    /// Dispatches accepted records to specialized mutation handlers based on event kind.
    ///
    /// # Arguments
    ///
    /// * `event` - Shared pointer to the incoming `Event`.
    fn on_event(&self, event: &Arc<Event>) {
        let Event::Etw(record) = &**event;
        let result = match (record.provider_id.data1, record.opcode) {
            // Process creation and baseline inventory share the same tree initialization path
            (KERNEL_PROCESS_GUID_PREFIX, OPCODE_PROCESS_START | OPCODE_PROCESS_DC_START) => {
                context::handle_process_start(record)
            }

            // Normal process termination
            (KERNEL_PROCESS_GUID_PREFIX, OPCODE_PROCESS_END) => {
                context::handle_process_exit(record)
            }

            // Module load and baseline module inventory share the same ingestion path
            (KERNEL_IMAGE_GUID_PREFIX, OPCODE_IMAGE_LOAD | OPCODE_IMAGE_DC_START) => {
                context::handle_image_load(record)
            }

            // Module unmap events
            (KERNEL_IMAGE_GUID_PREFIX, OPCODE_IMAGE_UNLOAD | OPCODE_IMAGE_DC_END) => {
                context::handle_image_unload(record)
            }

            // Rundown completion markers requiring no state change
            (KERNEL_PROCESS_GUID_PREFIX, OPCODE_PROCESS_DC_END) => Ok(()),

            _ => Ok(()),
        };

        if let Err(err) = result {
            log::warn!(
                target: "system_context",
                "Failed to process lifecycle event (Opcode: {}) for PID {}: {err}",
                record.opcode,
                record.process_id
            );
        }
    }
}
