//! Concurrent network socket and connection registry.

use std::sync::Arc;
use dashmap::DashMap;

use crate::context::identity::{ConnectionKey, ProcessKey};
use crate::context::models::network::NetworkConnection;

/// Concurrent registry managing network connections and mapping them to processes.
pub struct NetworkRegistry {
    /// Maps ConnectionKey to NetworkConnection.
    connections: DashMap<ConnectionKey, Arc<NetworkConnection>>,
    /// Maps ProcessKey to active connection keys.
    process_connections: DashMap<ProcessKey, Vec<ConnectionKey>>,
}

impl NetworkRegistry {
    /// Creates a new empty `NetworkRegistry`.
    ///
    /// # Returns
    ///
    /// An empty [`NetworkRegistry`].
    pub fn new() -> Self {
        Self {
            connections: DashMap::new(),
            process_connections: DashMap::new(),
        }
    }

    /// Registers a new active connection for a process.
    ///
    /// # Arguments
    ///
    /// * `conn` - The network connection metadata.
    ///
    /// # Returns
    ///
    /// An [`Arc<NetworkConnection>`] stored in the registry.
    pub fn register_connection(&self, conn: NetworkConnection) -> Arc<NetworkConnection> {
        let key = conn.key;
        let owner = conn.owner_process;
        let conn_arc = Arc::new(conn);

        self.connections.insert(key, Arc::clone(&conn_arc));
        self.process_connections
            .entry(owner)
            .or_default()
            .push(key);

        conn_arc
    }

    /// Resolves a connection by its synthetic key.
    ///
    /// # Arguments
    ///
    /// * `key` - The synthetic [`ConnectionKey`].
    ///
    /// # Returns
    ///
    /// `Some(Arc<NetworkConnection>)` if found, otherwise `None`.
    #[inline]
    pub fn get_by_key(&self, key: ConnectionKey) -> Option<Arc<NetworkConnection>> {
        self.connections.get(&key).map(|entry| Arc::clone(entry.value()))
    }

    /// Returns all connections associated with a specific process.
    ///
    /// # Arguments
    ///
    /// * `proc_key` - Synthetic process key.
    ///
    /// # Returns
    ///
    /// A vector of shared [`NetworkConnection`] references.
    pub fn process_connections(&self, proc_key: ProcessKey) -> Vec<Arc<NetworkConnection>> {
        let Some(keys) = self.process_connections.get(&proc_key) else {
            return Vec::new();
        };

        keys.iter()
            .filter_map(|k| self.get_by_key(*k))
            .collect()
    }

    /// Returns all connection keys associated with a specific process (alias).
    ///
    /// # Arguments
    ///
    /// * `proc_key` - Synthetic process key.
    ///
    /// # Returns
    ///
    /// A vector of shared [`NetworkConnection`] references.
    #[inline]
    pub fn get_process_connections(&self, proc_key: ProcessKey) -> Vec<Arc<NetworkConnection>> {
        self.process_connections(proc_key)
    }

    /// Total count of tracked connections.
    ///
    /// # Returns
    ///
    /// Total number of tracked socket connections.
    #[inline]
    pub fn len(&self) -> usize {
        self.connections.len()
    }

    /// Checks if the connection registry contains zero entries.
    ///
    /// # Returns
    ///
    /// `true` if zero connections are currently tracked.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.connections.is_empty()
    }

    /// Total count alias for backwards compatibility.
    ///
    /// # Returns
    ///
    /// Total number of tracked connections.
    #[inline]
    pub fn total_count(&self) -> usize {
        self.len()
    }
}

impl Default for NetworkRegistry {
    fn default() -> Self {
        Self::new()
    }
}
