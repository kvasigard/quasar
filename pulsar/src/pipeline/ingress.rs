//! Telemetry ingress pipeline and unified context ingestion pre-processor.
//!
//! # Architecture:
//! `IngressParser` is the **Single Source of Truth** for parsing, deduplicating, and correlating
//! all raw telemetry arriving from sensors (NT Kernel Logger ETW, KMDF Driver).
//!
//! It performs:
//! 1. Binary payload deserialization and multi-source deduplication.
//! 2. Immediate, idempotent ingestion into `SystemContext`.
//! 3. ETW call stack correlation (pairing `SyscallEnter` triggers with `Stack_Walk` traces).
//! 4. Transformation of raw byte records into strongly-typed `Event` domain variants.

use parking_lot::Mutex;

use crate::context::handlers::{
    handle_file_create, handle_file_name, handle_file_operation, handle_file_read_write,
    handle_image_load, handle_image_unload, handle_process_exit, handle_process_start,
};
use crate::helpers::stack_correlator::{StackCorrelator, StackWalkPayload};
use crate::pipeline::event::{Event, FileIoEvent};
use crate::sensors::etw::EventRecord;

/// 32-bit prefix for the Kernel Process Provider GUID `{3d6fa8d0-fe05-11d0-9dda-00c04fd7ba7c}`.
const KERNEL_PROCESS_GUID_PREFIX: u32 = 0x3d6fa8d0;

/// 32-bit prefix for the Kernel Image Load Provider GUID `{2cb15d1d-5fc1-11d2-abe1-00a0c911f518}`.
const KERNEL_IMAGE_GUID_PREFIX: u32 = 0x2cb15d1d;

/// 32-bit prefix for the PerfInfo Provider GUID `{ce1dbfb4-39ea-4851-89e0-a77cbfcce4ed}`.
const PERFINFO_GUID_PREFIX: u32 = 0xce1dbfb4;

/// 32-bit prefix for the StackWalk Provider GUID `{def2fe46-7bd6-4b80-bd94-f57fe20d0ce3}`.
const STACKWALK_GUID_PREFIX: u32 = 0xdef2fe46;

/// 32-bit prefix for the FileIo Provider GUID `{90cbdc39-4a3e-11d1-84f4-0000f80464e3}`.
const FILEIO_GUID_PREFIX: u32 = 0x90cbdc39;

const OPCODE_PROCESS_START: u8 = 1;
const OPCODE_PROCESS_END: u8 = 2;
const OPCODE_PROCESS_DC_START: u8 = 3;
const OPCODE_PROCESS_DC_END: u8 = 4;

const OPCODE_IMAGE_LOAD: u8 = 10;
const OPCODE_IMAGE_UNLOAD: u8 = 2;
const OPCODE_IMAGE_DC_START: u8 = 3;
const OPCODE_IMAGE_DC_END: u8 = 4;

const OPCODE_SYSCALL_ENTER: u8 = 51;
const OPCODE_STACKWALK: u8 = 32;

const OPCODE_FILEIO_NAME: u8 = 0;
const OPCODE_FILEIO_FILE_CREATE_V1: u8 = 32;
const OPCODE_FILEIO_FILE_DELETE_V1: u8 = 35;
const OPCODE_FILEIO_FILE_RUNDOWN_V1: u8 = 36;
const OPCODE_FILEIO_CREATE: u8 = 64;
const OPCODE_FILEIO_CLEANUP: u8 = 65;
const OPCODE_FILEIO_CLOSE: u8 = 66;
const OPCODE_FILEIO_READ: u8 = 67;
const OPCODE_FILEIO_WRITE: u8 = 68;
const OPCODE_FILEIO_SET_INFO: u8 = 69;
const OPCODE_FILEIO_DELETE: u8 = 70;
const OPCODE_FILEIO_RENAME: u8 = 71;
const OPCODE_FILEIO_DIR_ENUM: u8 = 72;
const OPCODE_FILEIO_FLUSH: u8 = 73;
const OPCODE_FILEIO_QUERY_INFO: u8 = 74;
const OPCODE_FILEIO_FS_CONTROL: u8 = 75;
const OPCODE_FILEIO_OP_END: u8 = 76;
const OPCODE_FILEIO_DIR_NOTIFY: u8 = 77;

/// Ingress parser & telemetry pre-processor holding the ETW stack correlator.
pub struct IngressParser {
    stack_correlator: Mutex<StackCorrelator>,
}

impl IngressParser {
    /// Creates a new `IngressParser` instance.
    ///
    /// # Returns
    ///
    /// An initialized [`IngressParser`].
    pub fn new() -> Self {
        Self {
            stack_correlator: Mutex::new(StackCorrelator::default()),
        }
    }

    /// Ingests a raw ETW record, updates `SystemContext` idempotently, and transforms it into a typed `Event`.
    ///
    /// # Arguments
    ///
    /// * `record` - The raw ETW telemetry record from the kernel trace session.
    ///
    /// # Returns
    ///
    /// `Some(Event)` if the record produced a complete domain event, or `None` if incomplete/buffered.
    #[tracing::instrument(name = "ingress_process_record", skip(self, record), level = "trace", fields(pid = record.process_id, opcode = record.opcode))]
    pub fn process_raw_record(&self, record: EventRecord) -> Option<Event> {
        let prefix = record.provider_id.data1;
        let opcode = record.opcode;

        match (prefix, opcode) {
            // Process creation and baseline rundown inventory
            (KERNEL_PROCESS_GUID_PREFIX, OPCODE_PROCESS_START | OPCODE_PROCESS_DC_START) => {
                match handle_process_start(&record) {
                    Ok(event) => Some(Event::ProcessStart(event)),
                    Err(e) => {
                        log::warn!(
                            target: "ingress",
                            "Failed to parse process start event for PID {}: {e}",
                            record.process_id
                        );
                        None
                    }
                }
            }

            // Process termination
            (KERNEL_PROCESS_GUID_PREFIX, OPCODE_PROCESS_END) => {
                match handle_process_exit(&record) {
                    Ok(event) => Some(Event::ProcessExit(event)),
                    Err(e) => {
                        log::warn!(
                            target: "ingress",
                            "Failed to parse process exit event for PID {}: {e}",
                            record.process_id
                        );
                        None
                    }
                }
            }

            // Module mapping / baseline DLL rundown
            (KERNEL_IMAGE_GUID_PREFIX, OPCODE_IMAGE_LOAD | OPCODE_IMAGE_DC_START) => {
                match handle_image_load(&record) {
                    Ok(event) => Some(Event::ImageLoad(event)),
                    Err(e) => {
                        log::debug!(
                            target: "ingress",
                            "Image load event for pre-existing or unmapped PID {}: {e}",
                            record.process_id
                        );
                        None
                    }
                }
            }

            // Module unmapping
            (KERNEL_IMAGE_GUID_PREFIX, OPCODE_IMAGE_UNLOAD | OPCODE_IMAGE_DC_END) => {
                match handle_image_unload(&record) {
                    Ok(event) => Some(Event::ImageUnload(event)),
                    Err(e) => {
                        log::warn!(
                            target: "ingress",
                            "Failed to parse image unload event for PID {}: {e}",
                            record.process_id
                        );
                        None
                    }
                }
            }

            // Syscall Enter trigger event (PerfInfo payload contains 64-bit SyscallAddress kernel function pointer)
            (PERFINFO_GUID_PREFIX, OPCODE_SYSCALL_ENTER) => {
                let syscall_address = if record.user_data.len() >= 8 {
                    Some(u64::from_ne_bytes(record.user_data[0..8].try_into().unwrap()))
                } else if record.user_data.len() >= 4 {
                    Some(u32::from_ne_bytes(record.user_data[0..4].try_into().unwrap()) as u64)
                } else {
                    None
                };

                let mut correlator = self.stack_correlator.lock();
                let matched = correlator.process_syscall_trigger(
                    record.process_id,
                    record.thread_id,
                    record.timestamp,
                    syscall_address,
                );

                matched.map(Event::CorrelatedSyscall)
            }

            // ETW Stack_Walk event
            (STACKWALK_GUID_PREFIX, OPCODE_STACKWALK) => {
                if let Some(payload) = StackWalkPayload::parse(&record.user_data) {
                    let mut correlator = self.stack_correlator.lock();
                    let matched = correlator.process_stack_walk(payload);
                    matched.map(Event::CorrelatedSyscall)
                } else {
                    None
                }
            }

            // File creation or open
            (FILEIO_GUID_PREFIX, OPCODE_FILEIO_CREATE) => {
                match handle_file_create(&record) {
                    Ok(event) => Some(Event::FileIo(FileIoEvent::Create(event))),
                    Err(e) => {
                        log::warn!(
                            target: "ingress",
                            "Failed to parse file create event for PID {}: {e}",
                            record.process_id
                        );
                        None
                    }
                }
            }

            // File name mapping and rundown
            (
                FILEIO_GUID_PREFIX,
                OPCODE_FILEIO_NAME
                | OPCODE_FILEIO_FILE_CREATE_V1
                | OPCODE_FILEIO_FILE_DELETE_V1
                | OPCODE_FILEIO_FILE_RUNDOWN_V1,
            ) => match handle_file_name(&record) {
                Ok(Some(event)) => Some(Event::FileIo(FileIoEvent::Create(event))),
                Ok(None) => None,
                Err(e) => {
                    log::warn!(
                        target: "ingress",
                        "Failed to parse file name event for PID {}: {e}",
                        record.process_id
                    );
                    None
                }
            },

            // File read operation
            (FILEIO_GUID_PREFIX, OPCODE_FILEIO_READ) => {
                match handle_file_read_write(&record, false) {
                    Ok(event) => Some(Event::FileIo(FileIoEvent::ReadWrite(event))),
                    Err(e) => {
                        log::warn!(
                            target: "ingress",
                            "Failed to parse file read event for PID {}: {e}",
                            record.process_id
                        );
                        None
                    }
                }
            }

            // File write operation
            (FILEIO_GUID_PREFIX, OPCODE_FILEIO_WRITE) => {
                match handle_file_read_write(&record, true) {
                    Ok(event) => Some(Event::FileIo(FileIoEvent::ReadWrite(event))),
                    Err(e) => {
                        log::warn!(
                            target: "ingress",
                            "Failed to parse file write event for PID {}: {e}",
                            record.process_id
                        );
                        None
                    }
                }
            }

            // File lifecycle and metadata operations (SetInfo, Delete, Rename, Close, Cleanup, Flush, DirEnum, DirNotify)
            (
                FILEIO_GUID_PREFIX,
                OPCODE_FILEIO_CLEANUP
                | OPCODE_FILEIO_CLOSE
                | OPCODE_FILEIO_SET_INFO
                | OPCODE_FILEIO_DELETE
                | OPCODE_FILEIO_RENAME
                | OPCODE_FILEIO_FLUSH
                | OPCODE_FILEIO_QUERY_INFO
                | OPCODE_FILEIO_FS_CONTROL
                | OPCODE_FILEIO_DIR_ENUM
                | OPCODE_FILEIO_DIR_NOTIFY,
            ) => match handle_file_operation(&record) {
                Ok(event) => Some(Event::FileIo(FileIoEvent::Operation(event))),
                Err(e) => {
                    log::warn!(
                        target: "ingress",
                        "Failed to parse file operation event for PID {}: {e}",
                        record.process_id
                    );
                    None
                }
            },

            // Operation end and rundown completion markers
            (FILEIO_GUID_PREFIX, OPCODE_FILEIO_OP_END) => None,
            (KERNEL_PROCESS_GUID_PREFIX, OPCODE_PROCESS_DC_END) => None,

            _ => None,
        }
    }
}

impl Default for IngressParser {
    fn default() -> Self {
        Self::new()
    }
}
