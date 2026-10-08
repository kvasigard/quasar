//! Kernel driver telemetry sensor and per-CPU ring buffer consumer.

pub mod consumer;
pub mod sensor;

pub use consumer::{CpuRingConsumer, DriverRingManager, MultiCpuRingManager, PerCpuConsumer};
pub use sensor::DriverSensor;
