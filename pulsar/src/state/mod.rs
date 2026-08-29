//! System state structure
//!
//! This module has the code relevant of saving the current system state
//! as observed by the telemetry events gathered by the implemented sensors.
//!
//! The SystemState structure is intended to be accessed globaly inside the
//! pulsar crate and exposes an DQL interface to make easy to query different
//! aspects about the system state.
//!
//! This object shall only be instanciated once and shall be updated as part of
//! the pipeline processing

use std::sync::{LazyLock, RwLock};

mod process_tree;
use crate::state::process_tree::ProcessTree;

pub(crate) static STATE: LazyLock<SystemState> = LazyLock::new(SystemState::default);

/// Returns a reference to the global `SystemState` singleton.
#[inline]
pub(crate) fn system_state() -> &'static SystemState {
    &STATE
}

pub(crate) struct SystemState {
    process_tree: RwLock<ProcessTree>,
}

impl Default for SystemState {
    fn default() -> Self {
        SystemState {
            process_tree: RwLock::new(ProcessTree::default()),
        }
    }

    // Interface Prototype
    //
    // For updates
    // system_state().update_process(process_key, |node| {
    //     node.command_line = "cmd.exe /c whoami".into();
    // });
    //
    // let target_key = system_state().get_process_key(pid, timestamp)?;
    //
    // Query metadata with a scoped closure (auto-locked & auto-released)
    // let parent_key = system_state().read_process(target_key, |p| p.parent_key);
    //
    // Query children keys
    // state.for_each_child(target_key, |child| {
    //    let name = child.image_file_name.to_lowercase();
    //    if name == "powershell.exe" || name == "cmd.exe" {
    //        ...
    //    }
    // });
}
