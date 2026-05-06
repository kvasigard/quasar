//! Inter-process communication and telemetry transport.
//!
//! This module implements the low-level primitives required to safely and 
//! efficiently move data between kernel-mode space and the user-mode daemon.
//!
//! It provides abstractions over specific Windows transport mechanisms, 
//! such as shared-memory ring buffers for high-throughput KMDF callbacks 
//! or Filter Communication Ports for file system events. This allows the 
//! rest of the application to consume telemetry streams without needing 
//! to manage the underlying memory mappings or synchronization constructs.