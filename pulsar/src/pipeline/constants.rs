//! Telemetry provider GUIDs and opcode constants for the ETW pipeline.
//!
//! This module centralizes the known NT Kernel Logger and custom provider identifiers
//! used during event ingestion, routing, and stack correlation.

use windows_sys::core::GUID;

/// Classic NT Kernel Logger Process Class MOF GUID (`3d6fa8d0-fe05-11d0-9dda-00c04fd7ba7c`).
pub const NT_KERNEL_PROCESS_GUID: GUID = GUID {
    data1: 0x3d6fa8d0,
    data2: 0xfe05,
    data3: 0x11d0,
    data4: [0x9d, 0xda, 0x00, 0xc0, 0x4f, 0xd7, 0xba, 0x7c],
};

/// Manifest `Microsoft-Windows-Kernel-Process` provider GUID (`22fb2cd6-0e7b-4226-a066-6180f7712465`).
pub const MANIFEST_KERNEL_PROCESS_GUID: GUID = GUID {
    data1: 0x22fb2cd6,
    data2: 0x0e7b,
    data3: 0x4226,
    data4: [0xa0, 0x66, 0x61, 0x80, 0xf7, 0x71, 0x24, 0x65],
};

/// NT Kernel Logger PerfInfo Class MOF GUID (`ce1dbfb4-137e-4da6-87b0-3f59aa102cbc`).
pub const NT_KERNEL_PERFINFO_GUID: GUID = GUID {
    data1: 0xce1dbfb4,
    data2: 0x137e,
    data3: 0x4da6,
    data4: [0x87, 0xb0, 0x3f, 0x59, 0xaa, 0x10, 0x2c, 0xbc],
};

/// NT Kernel Logger StackWalk Class GUID (`def2fe46-7bd6-4b80-bd94-f57fe20d0ce3`).
pub const NT_KERNEL_STACK_WALK_GUID: GUID = GUID {
    data1: 0xdef2fe46,
    data2: 0x7bd6,
    data3: 0x4b80,
    data4: [0xbd, 0x94, 0xf5, 0x7f, 0xe2, 0x0d, 0x0c, 0xe3],
};

/// Classic NT Kernel Logger Process Class provider GUID `data1` component (`3d6fa8d0-fe05-11d0-9dda-00c04fd7ba7c`).
pub const CLASSIC_NT_KERNEL_PROCESS_PROVIDER_GUID_DATA1: u32 = 0x3d6fa8d0;

/// Manifest `Microsoft-Windows-Kernel-Process` provider GUID `data1` component (`22fb2cd6-0e7b-4226-a066-6180f7712465`).
pub const NT_KERNEL_PROCESS_PROVIDER_GUID_DATA1: u32 = 0x22fb2cd6;

/// NT Kernel Logger PerfInfo provider GUID `data1` component (`ce1dbfb4-137e-4da6-87b0-3f59aa102cbc`).
pub const NT_KERNEL_PERFINFO_PROVIDER_GUID_DATA1: u32 = 0xce1dbfb4;

/// NT Kernel Logger StackWalk provider GUID `data1` component (`def2fe46-7bd6-4b80-bd94-f57fe20d0ce3`).
pub const NT_KERNEL_STACK_WALK_PROVIDER_GUID_DATA1: u32 = 0xdef2fe46;

/// Constant-time 128-bit GUID equality helper.
#[inline]
pub const fn guid_eq(a: &GUID, b: &GUID) -> bool {
    a.data1 == b.data1
        && a.data2 == b.data2
        && a.data3 == b.data3
        && a.data4[0] == b.data4[0]
        && a.data4[1] == b.data4[1]
        && a.data4[2] == b.data4[2]
        && a.data4[3] == b.data4[3]
        && a.data4[4] == b.data4[4]
        && a.data4[5] == b.data4[5]
        && a.data4[6] == b.data4[6]
        && a.data4[7] == b.data4[7]
}

/// Checks if a record's `provider_id` matches `expected` (supporting synthetic unit test records that only populate `data1`).
#[inline]
pub const fn guid_matches(record_guid: &GUID, expected: &GUID) -> bool {
    if record_guid.data2 == 0 && record_guid.data3 == 0 {
        record_guid.data1 == expected.data1
    } else {
        guid_eq(record_guid, expected)
    }
}

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
