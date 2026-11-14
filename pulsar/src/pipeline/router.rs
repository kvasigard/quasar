//! In-callback zero-copy ETW event decoder and priority-split router.
//!
//! # Why Decode Inside the Callback & Split Channels
//!
//! In a single-channel ETW architecture where every raw event copies its `UserData` into a
//! `Vec<u8>` and enters a shared FIFO queue, two failure modes arise under load:
//! 1. **Heap Allocation Churn:** Allocating and freeing a `Vec<u8>` for tens of thousands of
//!    events per second wastes CPU cycles on events whose payload is only read once.
//! 2. **State Starvation & Temporal Race:** When high-volume telemetry (or a process burst)
//!    fills a single channel, `Process::Start` events sit behind thousands of queued records.
//!    Meanwhile, the kernel driver's per-CPU ring buffer (`driver_rx`) delivers an immediate
//!    alert (such as `LsassAccessEvent`) for the new PID before `ProcessContextSink` has seen
//!    its `Process::Start` event, resulting in an `<unknown>` process attribution.
//!
//! [`PipelineEventRouter`] solves both problems by implementing [`TraceRouter`]:
//! - It decodes [`ProcessEvent`], [`SyscallEvent`], and [`StackWalkEvent`] directly from
//!   `&RawEvent` inside the callback using [`ByteCursor`](crate::pipeline::etw_schemas::ByteCursor).
//! - It routes state-building process lifecycle events to a dedicated high-priority `state_tx`
//!   channel and high-volume stack-correlated telemetry to `telemetry_tx`.

use std::sync::mpsc::{SyncSender, TrySendError};

use crate::model::events::{ProcessEvent, SyscallEvent};
use crate::pipeline::constants::{
    MANIFEST_KERNEL_PROCESS_GUID, NT_KERNEL_PERFINFO_GUID, NT_KERNEL_PROCESS_GUID,
    NT_KERNEL_STACK_WALK_GUID, guid_matches, process_opcodes, stack_walk_opcodes, syscall_opcodes,
};
use crate::pipeline::etw_schemas::nt_kernel::stack_walk::StackWalkEvent;
use crate::pipeline::event::Event;
use crate::sensors::etw::{ConsumerOutcome, RawEvent, TraceRouter};

/// Decoded telemetry item sent from [`PipelineEventRouter`] over `telemetry_tx` to the
/// [`Pipeline`](crate::pipeline::Pipeline) stack-correlation stage.
///
/// Carrying already-decoded structs inside `TelemetryEnvelope` ensures [`Pipeline::feed_envelope`](crate::pipeline::Pipeline::feed_envelope)
/// never has to re-parse raw byte slices on the dispatcher thread.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TelemetryEnvelope {
    /// A decoded domain [`Event`] that may optionally require out-of-band kernel `StackWalk` correlation.
    Trigger {
        /// The decoded domain event (e.g., [`Event::Syscall`]).
        event: Event,
        /// When `true`, [`CallStackCorrelator`](crate::pipeline::CallStackCorrelator) buffers
        /// `event` awaiting a matching [`TelemetryEnvelope::StackWalk`]. When `false` (for
        /// example when an inline `ExtendedData` stack trace was already extracted), the event
        /// bypasses correlation and is dispatched immediately.
        needs_async_stack: bool,
    },
    /// An out-of-band kernel stack walk event (`StackWalk_TypeGroup1`, Opcode 32) decoded
    /// inside the ETW callback and ready for `(EventTimeStamp, ProcessId, ThreadId)` correlation.
    StackWalk(StackWalkEvent),
}

/// Zero-copy, in-callback router that decodes `&RawEvent` payloads and splits state-critical
/// lifecycle events from high-volume stack-correlated telemetry.
///
/// # Concurrency & Backpressure Invariants
///
/// `PipelineEventRouter` is `Clone + Send + Sync` and uses non-blocking `SyncSender::try_send`
/// on both channels so the Win32 `ProcessTrace` callback thread can never deadlock or stall
/// waiting for the downstream dispatcher thread.
#[derive(Clone)]
pub struct PipelineEventRouter {
    /// High-priority bounded channel for state-building lifecycle events (`Process::Start`, `DCStart`, `End`, `DCEnd`, `Defunct`).
    state_tx: SyncSender<Event>,
    /// Bounded channel for stack-correlated telemetry ([`TelemetryEnvelope::Trigger`]) and [`TelemetryEnvelope::StackWalk`] frames.
    telemetry_tx: SyncSender<TelemetryEnvelope>,
}

impl PipelineEventRouter {
    /// Creates a new [`PipelineEventRouter`] writing to the priority-split `state_tx` and `telemetry_tx` channels.
    ///
    /// # Arguments
    ///
    /// * `state_tx` - High-priority channel drained first by [`EventDispatcher`](crate::pipeline::EventDispatcher).
    /// * `telemetry_tx` - Standard telemetry channel feeding [`Pipeline`](crate::pipeline::Pipeline) and [`CallStackCorrelator`](crate::pipeline::CallStackCorrelator).
    pub fn new(state_tx: SyncSender<Event>, telemetry_tx: SyncSender<TelemetryEnvelope>) -> Self {
        Self {
            state_tx,
            telemetry_tx,
        }
    }

    /// Maps a non-blocking `SyncSender::try_send` result to the corresponding [`ConsumerOutcome`].
    #[inline(always)]
    fn map_send_result<T>(res: Result<(), TrySendError<T>>) -> ConsumerOutcome {
        match res {
            Ok(()) => ConsumerOutcome::Dispatched,
            Err(TrySendError::Full(_)) => ConsumerOutcome::DroppedChannelFull,
            Err(TrySendError::Disconnected(_)) => ConsumerOutcome::ChannelDisconnected,
        }
    }
}

impl TraceRouter for PipelineEventRouter {
    #[inline]
    fn on_event(&self, event: &RawEvent, current_pid: u32) -> ConsumerOutcome {
        let provider_id = event.provider_id();
        let opcode = event.opcode();

        // 1. High-Priority State Path: Process lifecycle events (`Start`, `End`, `DCStart`, `DCEnd`, `Defunct`).
        // IMPORTANT: We evaluate this path BEFORE the `EventHeader.ProcessId` gate below because
        // kernel `Process::Start` and `DCStart` events are frequently logged in the context of
        // the `System` process (`PID 4`) or `Idle` (`PID 0`), with the actual target PID stored
        // inside the `UserData` payload!
        let is_process_provider = guid_matches(provider_id, &NT_KERNEL_PROCESS_GUID)
            || guid_matches(provider_id, &MANIFEST_KERNEL_PROCESS_GUID);

        if is_process_provider {
            let is_lifecycle_opcode = matches!(
                opcode,
                process_opcodes::START
                    | process_opcodes::END
                    | process_opcodes::DC_START
                    | process_opcodes::DC_END
                    | process_opcodes::DEFUNCT
            );
            if !is_lifecycle_opcode {
                return ConsumerOutcome::FilteredOut;
            }

            return match ProcessEvent::try_from(event) {
                Ok(proc_event) => {
                    Self::map_send_result(self.state_tx.try_send(Event::Process(proc_event)))
                }
                Err(_) => ConsumerOutcome::ParseError,
            };
        }

        // 2. Fast PID gate for high-volume telemetry (`StackWalk`, `SysCallEnter`):
        // Ignore `Idle` (0), `System` (4), and our own Pulsar agent PID (`current_pid`) to
        // prevent feedback loops where the agent's own syscalls generate more ETW events.
        let pid = event.process_id();
        if pid == 0 || pid == 4 || pid == current_pid {
            return ConsumerOutcome::FilteredOut;
        }

        // 3. Out-of-band Kernel StackWalk (Opcode 32)
        if guid_matches(provider_id, &NT_KERNEL_STACK_WALK_GUID) {
            if opcode != stack_walk_opcodes::STACK_WALK {
                return ConsumerOutcome::FilteredOut;
            }
            return match StackWalkEvent::try_from(event) {
                Ok(sw) => {
                    Self::map_send_result(self.telemetry_tx.try_send(TelemetryEnvelope::StackWalk(sw)))
                }
                Err(_) => ConsumerOutcome::ParseError,
            };
        }

        // 4. Kernel PerfInfo Syscall Enter (Opcode 51)
        if guid_matches(provider_id, &NT_KERNEL_PERFINFO_GUID) {
            if opcode != syscall_opcodes::SYSCALL_ENTER {
                return ConsumerOutcome::FilteredOut;
            }
            return match SyscallEvent::try_from(event) {
                Ok(syscall_evt) => {
                    let has_inline_stack = syscall_evt.stack_trace.is_some();
                    Self::map_send_result(self.telemetry_tx.try_send(TelemetryEnvelope::Trigger {
                        event: Event::Syscall(syscall_evt),
                        needs_async_stack: !has_inline_stack,
                    }))
                }
                Err(_) => ConsumerOutcome::ParseError,
            };
        }

        ConsumerOutcome::FilteredOut
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sensors::etw::SyntheticEvent;
    use std::sync::mpsc;

    #[test]
    fn test_pipeline_router_splits_process_to_state_tx_and_syscall_to_telemetry_tx() {
        let (state_tx, state_rx) = mpsc::sync_channel(16);
        let (telemetry_tx, telemetry_rx) = mpsc::sync_channel(16);
        let router = PipelineEventRouter::new(state_tx, telemetry_tx);

        // 1. Build a Process::Start synthetic event
        let mut proc_data = Vec::new();
        proc_data.extend_from_slice(&(0xAAAA_BBBBusize).to_ne_bytes()); // UniqueProcessKey
        proc_data.extend_from_slice(&2000u32.to_ne_bytes()); // ProcessId
        proc_data.extend_from_slice(&1000u32.to_ne_bytes()); // ParentId
        proc_data.extend_from_slice(&1u32.to_ne_bytes()); // SessionId
        proc_data.extend_from_slice(&0i32.to_ne_bytes()); // ExitStatus
        proc_data.extend_from_slice(&(0x200000usize).to_ne_bytes()); // DirectoryTableBase
        proc_data.extend_from_slice(&[1u8, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0]); // SID
        proc_data.extend_from_slice(b"notepad.exe\0");
        let cmd: Vec<u8> = "notepad.exe\0"
            .encode_utf16()
            .flat_map(|u| u.to_ne_bytes())
            .collect();
        proc_data.extend_from_slice(&cmd);

        let proc_syn = SyntheticEvent::new(
            NT_KERNEL_PROCESS_GUID,
            2,
            process_opcodes::START,
            2000,
            2004,
            10_000,
            proc_data,
        );

        assert_eq!(router.on_event(&proc_syn, 9999), ConsumerOutcome::Dispatched);
        let state_evt = state_rx.try_recv().expect("Process event must arrive on state_rx");
        assert!(matches!(state_evt, Event::Process(p) if p.image_file_name == "notepad.exe"));
        assert!(telemetry_rx.try_recv().is_err());

        // 2. Build a SysCallEnter synthetic event from non-self PID
        let sys_syn = SyntheticEvent::new(
            NT_KERNEL_PERFINFO_GUID,
            2,
            syscall_opcodes::SYSCALL_ENTER,
            2000,
            2004,
            10_500,
            (0x7FFF_1234usize).to_ne_bytes().to_vec(),
        );
        assert_eq!(router.on_event(&sys_syn, 9999), ConsumerOutcome::Dispatched);
        let env = telemetry_rx
            .try_recv()
            .expect("Syscall must arrive on telemetry_rx");
        assert!(matches!(
            env,
            TelemetryEnvelope::Trigger {
                event: Event::Syscall(_),
                needs_async_stack: true
            }
        ));

        // 3. Self-PID syscall is filtered out with zero channel writes
        let self_sys = SyntheticEvent::new(
            NT_KERNEL_PERFINFO_GUID,
            2,
            syscall_opcodes::SYSCALL_ENTER,
            9999,
            2004,
            10_600,
            (0x7FFF_1234usize).to_ne_bytes().to_vec(),
        );
        assert_eq!(
            router.on_event(&self_sys, 9999),
            ConsumerOutcome::FilteredOut
        );
    }
}
