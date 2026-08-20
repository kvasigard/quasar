//! Thread entity, impersonation, and execution context model.

use std::sync::atomic::{AtomicI64, AtomicU32, Ordering};
use crate::context::identity::{ProcessKey, ThreadKey};
use crate::context::models::token::TokenContext;

/// Execution state of a thread.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreadExecutionState {
    /// Actively scheduled and running.
    Running,
    /// Suspended by debugger or API.
    Suspended,
    /// Terminated.
    Terminated,
}

/// Metadata and state for an individual thread.
#[derive(Debug)]
pub struct ThreadContext {
    /// Synthetic unique key for this thread instance.
    pub key: ThreadKey,
    /// Synthetic key of the owning process.
    pub owner_process: ProcessKey,
    /// Operating system Thread ID (TID).
    pub tid: u32,
    /// Virtual start address where thread execution began.
    pub start_address: u64,
    /// Optional Thread Environment Block (TEB) base address.
    pub teb_base: Option<u64>,
    /// Thread creation timestamp.
    pub create_time: i64,
    /// Thread termination timestamp (0 if alive).
    pub exit_time: AtomicI64,
    /// Win32 exit code.
    pub exit_status: AtomicU32,
    /// Thread impersonation token if explicitly impersonating another security context.
    pub impersonation_token: parking_lot::RwLock<Option<TokenContext>>,
}

impl ThreadContext {
    /// Instantiates a new tracked thread.
    ///
    /// # Arguments
    ///
    /// * `key` - Synthetic thread key.
    /// * `owner_process` - Owning process key.
    /// * `tid` - Operating system Thread ID.
    /// * `start_address` - Initial instruction pointer address.
    /// * `create_time` - Thread start timestamp.
    ///
    /// # Returns
    ///
    /// An initialized [`ThreadContext`].
    pub fn new(
        key: ThreadKey,
        owner_process: ProcessKey,
        tid: u32,
        start_address: u64,
        create_time: i64,
    ) -> Self {
        Self {
            key,
            owner_process,
            tid,
            start_address,
            teb_base: None,
            create_time,
            exit_time: AtomicI64::new(0),
            exit_status: AtomicU32::new(0),
            impersonation_token: parking_lot::RwLock::new(None),
        }
    }

    /// Checks if this thread is currently alive.
    ///
    /// # Returns
    ///
    /// `true` if exit_time is 0, indicating the thread has not terminated.
    pub fn is_alive(&self) -> bool {
        self.exit_time.load(Ordering::Relaxed) == 0
    }

    /// Marks this thread as terminated.
    ///
    /// # Arguments
    ///
    /// * `exit_status` - Win32 exit status code.
    /// * `timestamp` - Termination timestamp in FILETIME format.
    pub fn mark_terminated(&self, exit_status: u32, timestamp: i64) {
        self.exit_status.store(exit_status, Ordering::Release);
        self.exit_time.store(timestamp, Ordering::Release);
    }
}
