//! Synthetic identity types and entity identifiers.
//!
//! Windows rapidly recycles OS identifiers (Process IDs, Thread IDs, File Handles).
//! Relying directly on raw OS IDs leads to severe race conditions and corrupted forensic state.
//!
//! This module defines 64-bit monotonically incrementing synthetic keys that uniquely identify
//! an entity across its exact temporal lifecycle.

use std::sync::atomic::{AtomicU64, Ordering};

/// Monotonically increasing synthetic identifier for a distinct process execution instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProcessKey(pub u64);

impl ProcessKey {
    /// Generates a globally unique, monotonically incrementing `ProcessKey`.
    ///
    /// # Returns
    ///
    /// A new, unique [`ProcessKey`].
    #[inline]
    pub fn new() -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(1);
        Self(COUNTER.fetch_add(1, Ordering::Relaxed))
    }

    /// Creates a synthetic key from an explicit raw identifier.
    ///
    /// # Arguments
    ///
    /// * `raw` - The raw 64-bit numeric value.
    ///
    /// # Returns
    ///
    /// A [`ProcessKey`] wrapping the provided raw integer.
    #[inline]
    pub const fn from_raw(raw: u64) -> Self {
        Self(raw)
    }

    /// Returns the underlying raw 64-bit numeric value.
    ///
    /// # Returns
    ///
    /// The primitive `u64` representation of this key.
    #[inline]
    pub const fn as_u64(&self) -> u64 {
        self.0
    }
}

impl Default for ProcessKey {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for ProcessKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ProcKey(#{})", self.0)
    }
}

/// Monotonically increasing synthetic identifier for a thread instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ThreadKey(pub u64);

impl ThreadKey {
    /// Generates a globally unique, monotonically incrementing `ThreadKey`.
    ///
    /// # Returns
    ///
    /// A new, unique [`ThreadKey`].
    #[inline]
    pub fn new() -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(1);
        Self(COUNTER.fetch_add(1, Ordering::Relaxed))
    }

    /// Creates a thread key from an explicit raw identifier.
    ///
    /// # Arguments
    ///
    /// * `raw` - The raw 64-bit numeric value.
    ///
    /// # Returns
    ///
    /// A [`ThreadKey`] wrapping the provided raw integer.
    #[inline]
    pub const fn from_raw(raw: u64) -> Self {
        Self(raw)
    }

    /// Returns the underlying raw 64-bit numeric value.
    ///
    /// # Returns
    ///
    /// The primitive `u64` representation of this key.
    #[inline]
    pub const fn as_u64(&self) -> u64 {
        self.0
    }
}

impl Default for ThreadKey {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for ThreadKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ThreadKey(#{})", self.0)
    }
}

/// Monotonically increasing synthetic identifier for a unique filesystem file path / object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FileKey(pub u64);

impl FileKey {
    /// Generates a globally unique, monotonically incrementing `FileKey`.
    ///
    /// # Returns
    ///
    /// A new, unique [`FileKey`].
    #[inline]
    pub fn new() -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(1);
        Self(COUNTER.fetch_add(1, Ordering::Relaxed))
    }

    /// Creates a file key from an explicit raw identifier.
    ///
    /// # Arguments
    ///
    /// * `raw` - The raw 64-bit numeric value.
    ///
    /// # Returns
    ///
    /// A [`FileKey`] wrapping the provided raw integer.
    #[inline]
    pub const fn from_raw(raw: u64) -> Self {
        Self(raw)
    }

    /// Returns the underlying raw 64-bit numeric value.
    ///
    /// # Returns
    ///
    /// The primitive `u64` representation of this key.
    #[inline]
    pub const fn as_u64(&self) -> u64 {
        self.0
    }
}

impl Default for FileKey {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for FileKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "FileKey(#{})", self.0)
    }
}

/// Monotonically increasing synthetic identifier for a network connection (socket).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ConnectionKey(pub u64);

impl ConnectionKey {
    /// Generates a globally unique, monotonically incrementing `ConnectionKey`.
    ///
    /// # Returns
    ///
    /// A new, unique [`ConnectionKey`].
    #[inline]
    pub fn new() -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(1);
        Self(COUNTER.fetch_add(1, Ordering::Relaxed))
    }

    /// Creates a connection key from an explicit raw identifier.
    ///
    /// # Arguments
    ///
    /// * `raw` - The raw 64-bit numeric value.
    ///
    /// # Returns
    ///
    /// A [`ConnectionKey`] wrapping the provided raw integer.
    #[inline]
    pub const fn from_raw(raw: u64) -> Self {
        Self(raw)
    }

    /// Returns the underlying raw 64-bit numeric value.
    ///
    /// # Returns
    ///
    /// The primitive `u64` representation of this key.
    #[inline]
    pub const fn as_u64(&self) -> u64 {
        self.0
    }
}

impl Default for ConnectionKey {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for ConnectionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ConnKey(#{})", self.0)
    }
}

/// Monotonically increasing synthetic identifier for an interaction event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InteractionId(pub u64);

impl InteractionId {
    /// Generates a globally unique, monotonically incrementing `InteractionId`.
    ///
    /// # Returns
    ///
    /// A new, unique [`InteractionId`].
    #[inline]
    pub fn new() -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(1);
        Self(COUNTER.fetch_add(1, Ordering::Relaxed))
    }

    /// Creates an interaction ID from an explicit raw identifier.
    ///
    /// # Arguments
    ///
    /// * `raw` - The raw 64-bit numeric value.
    ///
    /// # Returns
    ///
    /// An [`InteractionId`] wrapping the provided raw integer.
    #[inline]
    pub const fn from_raw(raw: u64) -> Self {
        Self(raw)
    }

    /// Returns the underlying raw 64-bit numeric value.
    ///
    /// # Returns
    ///
    /// The primitive `u64` representation of this ID.
    #[inline]
    pub const fn as_u64(&self) -> u64 {
        self.0
    }
}

impl Default for InteractionId {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for InteractionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Interaction(#{})", self.0)
    }
}

/// Universal enum representing a typed reference to any system entity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EntityId {
    /// A process instance.
    Process(ProcessKey),
    /// A thread instance.
    Thread(ThreadKey),
    /// A filesystem file path/node.
    File(FileKey),
    /// A network connection / socket.
    Network(ConnectionKey),
    /// A memory region identified by owner process and virtual base address.
    Memory(ProcessKey, u64),
}

impl EntityId {
    /// Returns the associated `ProcessKey` if this entity is a process.
    ///
    /// # Returns
    ///
    /// `Some(ProcessKey)` if this variant is [`EntityId::Process`], otherwise `None`.
    #[inline]
    pub fn as_process(&self) -> Option<ProcessKey> {
        match self {
            Self::Process(k) => Some(*k),
            _ => None,
        }
    }
}
