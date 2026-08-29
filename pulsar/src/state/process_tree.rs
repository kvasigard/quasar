//! Represents all the processes that lived inside the system.
//!
//! This struct shall save ProcessNode structures and ensure their state
//! is valid.

use std::collections::HashMap;

use crate::model::{ProcessKey, ProcessNode};

// We have the following cases that we need to take care of:
// ### Insertions
// 1. A process start event arrives and no this process is not in the ProcessTree.
// 2. A process start event arrives and this process is already in the ProcessTree.
// 3. A process end event arrives and the process is in the ProcessTree.
// 4. A process end event arrives and the process ins not in the ProcessTree.
//
// ### Queries
// The way of asking for a process is by its PID. Despite that we can't use the PID as
// the primary key of an object mainly because:
// 1. Windows system might reuse PIDs after a process terminates.
// 2. We need to save the information of processes that have been already terminated.
//
// To solve this problem exists the ProcessKey struct, which tracks the PID + Timestamp
// of the process creation. The best option I can think now is that whoever queries for a process
// might need to supply the PID and a Timestamp. With the timestamp of the event (which comes
// with the event) we can infer if we need to provide the dead process or the living one.
//
// [      Process A lifetime      ]      [      Process B lifetime      ]
//                                 * Query timestamp                      * Query processing time
//
// In this case we can differ that the process was asking for process A because process B was
// not even spawned.

pub(super) struct ProcessTree(HashMap<ProcessKey, ProcessNode>);

impl ProcessTree {
    /// Inserts a new process into the ProcessTree
    fn insert(&mut self, process: ProcessNode) {
        let key = ProcessKey::new(process.process_id, process.creation_timestamp);
        self.0.insert(key, process);
    }

    /// Finds a process directly by its exact ProcessKey
    pub fn get(&self, key: &ProcessKey) -> Option<&ProcessNode> {
        self.0.get(key)
    }
}

impl Default for ProcessTree {
    fn default() -> Self {
        Self(HashMap::new())
    }
}
