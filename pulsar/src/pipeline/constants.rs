//! Telemetry provider GUIDs and opcode constants for the ETW pipeline.
//!
//! This module centralizes the known NT Kernel Logger and custom provider identifiers
//! used during event ingestion, routing, and stack correlation.

/// NT Kernel Logger Process Class provider GUID `data1` component (`22fb2cd6-0e7b-4226-a066-6180f7712465`).
pub const NT_KERNEL_PROCESS_PROVIDER_GUID_DATA1: u32 = 0x22fb2cd6;

/// NT Kernel Logger PerfInfo provider GUID `data1` component (`ce1dbfb4-39ea-4851-89e0-a77cbfcce4ed`).
pub const NT_KERNEL_PERFINFO_PROVIDER_GUID_DATA1: u32 = 0xce1dbfb4;

/// NT Kernel Logger StackWalk provider GUID `data1` component (`def2fe46-7bd6-4b80-bd94-f57fe20d0ce3`).
pub const NT_KERNEL_STACK_WALK_PROVIDER_GUID_DATA1: u32 = 0xdef2fe46;

/// Process lifecycle event opcodes emitted by the NT Kernel Logger.
pub mod process_opcodes {
    /// Process creation event (EventType 1).
    pub const START: u8 = 1;

    /// Process termination event (EventType 2).
    pub const END: u8 = 2;

    /// Rundown snapshot event for processes active at trace start (EventType 3).
    pub const DC_START: u8 = 3;

    /// Rundown snapshot event for processes active at trace end (EventType 4).
    pub const DC_END: u8 = 4;

    /// Rundown snapshot event for lingering zombie process objects (EventType 39).
    pub const DEFUNCT: u8 = 39;
}

/// System call event opcodes emitted by the NT Kernel Logger PerfInfo group.
pub mod syscall_opcodes {
    /// System call entry transition (EventType 51).
    pub const SYSCALL_ENTER: u8 = 51;

    /// System call return transition (EventType 52).
    pub const SYSCALL_EXIT: u8 = 52;
}

/// Stack walk event opcodes emitted by the NT Kernel Logger.
pub mod stack_walk_opcodes {
    /// Kernel instruction pointer call stack event (EventType 32).
    pub const STACK_WALK: u8 = 32;
}
