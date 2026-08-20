# 08 — Error Handling Architecture

Error handling in systems-level software often degrades into two extremes: either functions return untyped string errors (like `anyhow::Result` or `String`) where critical failure codes are lost in text, or the entire codebase uses a single monolithic error enum containing dozens of unrelated variants from every module in the project.

Quasar adopts a balanced, domain-partitioned error architecture in `pulsar/src/error.rs`. Each major subsystem defines its own strongly-typed error enum representing only the specific ways that subsystem can fail, and these errors naturally convert into a unified `AppError` type at application boundaries.

```
                              ┌───────────────────────────┐
                              │    AppError (Top-Level)   │
                              └─────────────┬─────────────┘
                                            │
     ┌──────────────────┬───────────────────┼───────────────────┬──────────────────┐
     ▼                  ▼                   ▼                   ▼                  ▼
Win32Error        HandlerError        BootstrapError       DriverError          EtwError
(OS Error & Msg)  (Binary Packets)    (Privileges & INF)   (SCM & IOCTLs)       (Kernel Trace)
```

## Why Domain-Partitioned Errors Are Better

Partitioning error types by domain provides several distinct advantages:

First, it keeps internal subsystem interfaces clean and intuitive. When you call a function in the driver module, the compiler guarantees that it can only return a `DriverError` (such as a Service Control Manager failure or an IOCTL error), rather than an irrelevant error variant from the ETW sensor or telemetry parser.

Second, it preserves low-level numeric operating system codes. When a Windows API fails, our `Win32Error` struct automatically captures the thread-local `GetLastError()` code and retrieves the official English explanation using `FormatMessageW`. This ensures that diagnostic logs contain the exact error code (like `0x00000005: Access Denied`) rather than vague error messages.

Third, it supports seamless root-cause chaining. Every error type implements the standard `std::error::Error` trait and provides `source()` implementations. When an error bubbles up to the top level, diagnostic tools can inspect the entire chain of causality, from high-level application failure down to the original Win32 error code.

## Subsystem Error Categories

The error architecture is organized into five dedicated domain types:

`Win32Error` represents thread-local Windows operating system errors. Calling `Win32Error::last()` automatically queries `GetLastError()` and decodes the message string via `FormatMessageW`.

`BootstrapError` represents pre-flight initialization failures. Its variants include `AdminPrivilegesRequired` (when the user runs the agent in a standard non-elevated command prompt), `PackageFilesNotFound` (when `singularity.inf` is missing from the directory), `PplVerificationFailed` (when the operating system rejects PPL protection), and `DriverInstallationFailed`.

`DriverError` captures communication and lifecycle failures with the kernel driver, including SCM connection errors, service creation or startup failures, and invalid device handle or IOCTL errors.

`EtwError` covers failures related to the Windows event trace sessions, such as failing to start the NT Kernel Logger, encountering buffer overflows, or failing to open the real-time trace stream.

`HandlerError` covers binary telemetry parsing errors, such as receiving a packet that is shorter than the minimum expected header size (`PayloadTooShort`) or encountering an event for a process whose start record was missed.

## Unified Application Error (`AppError`)

At cross-cutting boundaries (such as in `main.rs`), all domain-specific errors automatically convert into the top-level `AppError` enum using standard `From` trait implementations:

```rust
pub enum AppError {
    Win32(Win32Error),
    Bootstrap(BootstrapError),
    Driver(DriverError),
    Etw(EtwError),
    Handler(HandlerError),
    Internal(String),
}
```

This allows functions throughout the codebase to use the standard Rust question mark operator (`?`) to bubble errors upward effortlessly without losing type information or context.

## Error Expansion Notes

When adding new features or failure modes to Quasar, follow these guidelines:

If you are adding a new error variant to an existing subsystem, add the variant directly to the relevant enum in `pulsar/src/error.rs` (for example, adding `DriverError::InvalidDeviceVersion`). Update the `Display` implementation for that enum to provide a clear, human-readable error description, and if the variant wraps an underlying `Win32Error`, add a match arm in the `Error::source()` implementation.

If you are introducing an entirely new subsystem (such as a network communications client or a cloud exporter), create a dedicated error enum for it (like `pub enum NetworkError`). Implement `Display` and `std::error::Error`, add a corresponding variant to `AppError` (like `AppError::Network(NetworkError)`), and implement `From<NetworkError> for AppError`.
