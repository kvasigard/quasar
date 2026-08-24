//! Fluent network connection query interface.

use std::sync::Arc;

use crate::context::SystemContext;
use crate::context::identity::ProcessKey;
use crate::context::models::network::{NetworkConnection, SocketProtocol};

/// Fluent query builder for filtering and inspecting network connections.
pub struct NetworkQuery<'a> {
    ctx: &'a SystemContext,
}

impl<'a> NetworkQuery<'a> {
    /// Creates a new `NetworkQuery` builder.
    pub fn new(ctx: &'a SystemContext) -> Self {
        Self { ctx }
    }

    /// Queries all network connections owned by a specific process.
    pub fn by_process(&self, proc_key: ProcessKey) -> Vec<Arc<NetworkConnection>> {
        self.ctx.network.process_connections(proc_key)
    }

    /// Queries all network connections matching a specific remote port.
    pub fn by_remote_port(&self, port: u16) -> Vec<Arc<NetworkConnection>> {
        self.ctx
            .network
            .all_connections()
            .into_iter()
            .filter(|conn| conn.remote_addr.port() == port)
            .collect()
    }

    /// Queries all network connections matching a specific protocol.
    pub fn by_protocol(&self, protocol: SocketProtocol) -> Vec<Arc<NetworkConnection>> {
        self.ctx
            .network
            .all_connections()
            .into_iter()
            .filter(|conn| conn.protocol == protocol)
            .collect()
    }

    /// Queries all outbound external connections (excluding loopback 127.0.0.1 / ::1).
    pub fn outbound_external(&self) -> Vec<Arc<NetworkConnection>> {
        self.ctx
            .network
            .all_connections()
            .into_iter()
            .filter(|conn| !conn.remote_addr.ip().is_loopback())
            .collect()
    }
}
