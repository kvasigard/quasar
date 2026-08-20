# 06 — Bootstrap, Service Lifecycle & Teardown

Before Pulsar begins ingesting telemetry or evaluating detection rules, it executes an automated pre-flight bootstrap sequence. This process verifies that the execution environment has the necessary privileges, stages and starts the underlying kernel driver, elevates the process to PPL-Antimalware, and prepares the system for real-time monitoring.

```
 [1. Check Administrator Token]
         │
         ▼
 [2. Locate `singularity.inf` & `singularity.sys`]
         │
         ▼
 [3. Stage Driver into Driver Store (DiInstallDriverW)]
         │
         ▼
 [4. Start Driver Service via Service Control Manager (SCM)]
         │
         ▼
 [5. Connect to Driver & Request PPL-Antimalware Elevation]
         │
         ▼
 [6. Verify Protection Level via GetProcessInformation() (Level == 3)]
```

## Automated Driver Staging and Hot-Upgrades

Instead of directly creating raw registry entries to force the operating system to load a `.sys` file, Quasar stages the driver package through the Windows Driver Store using the `DiInstallDriverW` API. This approach ensures that the driver package (`singularity.inf` and `singularity.sys`) is properly cataloged, verified against Windows code signing requirements, and stored in the official `System32\DriverStore` directory.

Once staged, the driver service is registered and managed through the Windows Service Control Manager (SCM) using our module in `drivers/scm.rs`.

If the Singularity driver service is already registered from a previous run, Pulsar automatically checks whether an upgrade is needed. It retrieves the path of the currently installed driver from SCM and performs a fast byte-by-byte comparison against the local driver binary. If the local binary is newer or different (for example, after a software update), Pulsar automatically stops the old service, unloads the driver, stages the new version, and restarts the service without requiring manual uninstallation.

## Zero-CPU Shutdown Mechanics

A common anti-pattern in daemon applications is keeping the main thread alive by looping over an atomic boolean and sleeping:

```rust
// Inefficient polling pattern
while RUNNING.load(Ordering::Relaxed) {
    std::thread::sleep(Duration::from_millis(100));
}
```

This sleep-loop approach has two significant drawbacks: it wastes CPU cycles waking up multiple times every second across thousands of enterprise endpoints, and it introduces noticeable shutdown latency because the application has to wait for the sleep timer to expire before reacting to a shutdown signal.

Quasar replaces this with a bounded synchronization channel from `crossbeam-channel`:

```rust
fn wait_for_shutdown() {
    let (shutdown_tx, shutdown_rx) = crossbeam_channel::bounded::<()>(1);

    ctrlc::set_handler(move || {
        log::info!("Shutdown signal received. Initiating graceful teardown...");
        let _ = shutdown_tx.send(());
    }).expect("Error setting Ctrl-C handler");

    // The main thread is suspended in the OS futex queue consuming strictly 0.0% CPU
    let _ = shutdown_rx.recv();
}
```

While waiting for the shutdown signal, the main thread is suspended in the operating system kernel, consuming exactly zero CPU cycles. The exact microsecond that Ctrl+C is pressed, the signal handler pushes a message into the channel and the operating system immediately awakens the main thread.

## Graceful Pipeline Draining

When shutting down, calling `std::process::exit(0)` abruptly is dangerous because it leaves active kernel trace sessions running, drops in-flight telemetry events, and prevents analytical sinks from finishing their work.

Quasar implements a deterministic, cascading teardown:
1. The main thread calls `kernel_session.stop()`, safely instructing Windows to close the ETW trace session.
2. The consumer thread finishes reading any remaining kernel buffers, exits its loop, and drops the sender channel (`drop(tx)`).
3. The dispatcher worker threads naturally detect that the channel is closed (`rx.recv()` returns `Err(Disconnected)`), finish evaluating all remaining events in the buffer, and terminate cleanly.
4. The main thread joins all worker handles and prints a final confirmation before exiting.

## Lifecycle Expansion Notes

When you need to modify or expand the bootstrap and lifecycle process, keep the following in mind:

If you are adding pre-flight checks (such as verifying minimum OS build numbers, checking for virtualization-based security, or validating required Windows privileges like `SeDebugPrivilege`), add them as individual helper functions in `bootstrap.rs` and call them early in `pulsar::bootstrap::initialize()`. Always return typed `BootstrapError` variants so callers understand exactly why initialization failed.

To support command-line service uninstallation, Pulsar provides the `--uninstall` flag. When passed, `main.rs` skips the initialization pipeline and directly calls `pulsar::drivers::scm::unload_driver()`, which stops the service and deletes its registration from the SCM database.
