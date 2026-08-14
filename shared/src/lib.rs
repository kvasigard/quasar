//! Common types, traits, and IOCTL message contracts shared between user-mode and kernel-mode.
//!
//! Designed for `no_std` environments so that it can be directly consumed by both
//! user-mode agents (`pulsar`) and kernel drivers (`singularity`).

#![no_std]

pub mod ioctl;
