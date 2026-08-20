//! Network connection and socket telemetry models.

use std::net::SocketAddr;
use crate::context::identity::{ConnectionKey, ProcessKey};

/// Transport protocol used by a network socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SocketProtocol {
    /// Transmission Control Protocol.
    Tcp,
    /// User Datagram Protocol.
    Udp,
    /// Raw socket connection.
    Raw,
}

/// Information representing an active or recent network connection.
#[derive(Debug, Clone)]
pub struct NetworkConnection {
    /// Unique synthetic key for this connection instance.
    pub key: ConnectionKey,
    /// Owner process that initiated or accepted this connection.
    pub owner_process: ProcessKey,
    /// Transport protocol (TCP / UDP).
    pub protocol: SocketProtocol,
    /// Local IP endpoint (IP + Port).
    pub local_addr: SocketAddr,
    /// Remote IP endpoint (IP + Port).
    pub remote_addr: SocketAddr,
    /// Timestamp when the connection was established.
    pub start_time: i64,
    /// Timestamp when the socket closed (None if currently open).
    pub end_time: Option<i64>,
}
