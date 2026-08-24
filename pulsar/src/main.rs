use std::thread::JoinHandle;

use clap::Parser;
use crossbeam_channel::Sender;
use pulsar::cli::Cli;
use pulsar::error::AppError;
use pulsar::pipeline::{DispatcherHandle, EventDispatcher};
use pulsar::sensors::etw::director::SessionDirector;
use pulsar::sensors::etw::{EtwSession, EventRecord, KernelSession, KernelSessionBuilder};
use pulsar::sinks::direct_sys::DirectSyscallSink;
use pulsar::profiling::init_profiling;
use windows_sys::Win32::Foundation::ERROR_SERVICE_DEPENDENCY_FAIL;

/// Application entry point for the Pulsar EDR agent.
///
/// Parses command-line arguments, initializes structured tracing/profiling, orchestrates driver bootstrap,
/// configures the event pipeline and ETW session, and manages execution lifecycle until termination.
fn main() {
    let cli = Cli::parse();
    let _profiling_guard = init_profiling(
        cli.log_mode,
        cli.log_file.as_ref(),
        cli.profile.as_ref(),
    );

    log::debug!("Parsed CLI configuration: {:?}", cli);

    if cli.uninstall {
        handle_uninstall();
    }

    log::info!("Starting Quasar EDR Engine (Pulsar)...");

    // Initialize driver and request PPL elevation
    init_driver_and_ppl(cli.skip_driver);

    // Setup event bus and dispatching pipeline
    let enable_syscalls = !cli.disable_syscalls;
    let enable_context = !cli.disable_context;

    let (tx, dispatcher_handle) = setup_event_pipeline(enable_syscalls, enable_context);

    // Build and start NT Kernel Logger ETW session
    let (kernel_session, consumer_handle) =
        match start_kernel_session(enable_syscalls, enable_context, tx) {
            Ok(handles) => handles,
            Err(e) => {
                log::error!("Failed to initialize and start ETW session: {}", e);
                return;
            }
        };

    log::info!(
        "Quasar EDR Engine is active and capturing telemetry. Press Ctrl+C to safely stop..."
    );

    // Wait for user termination signal
    wait_for_shutdown();

    // Teardown session and join worker threads
    teardown_session(kernel_session, consumer_handle, dispatcher_handle);
}

/// Handles the `--uninstall` CLI flag by requesting SCM to stop and delete the driver service.
///
/// Terminates the process upon completion, exiting with code `0` on success or `1` on failure.
fn handle_uninstall() {
    log::info!("Uninstall option detected. Initiating Singularity driver teardown...");
    match pulsar::drivers::scm::unload_driver() {
        Ok(_) => {
            log::info!("Singularity driver successfully stopped and unregistered.");
            std::process::exit(0);
        }
        Err(e) => {
            log::error!("Failed to unload/uninstall Singularity driver: {}", e);
            std::process::exit(1);
        }
    }
}

/// Orchestrates pre-flight driver installation, SCM service start, and PPL-Antimalware elevation.
///
/// If `skip_driver` is `false`, invokes [`pulsar::bootstrap::initialize`] to verify administrator
/// privileges, install/load the Singularity kernel driver, and elevate the process to PPL.
/// If initialization fails, logs an error and exits the process with `ERROR_SERVICE_DEPENDENCY_FAIL`.
///
/// # Arguments
///
/// * `skip_driver` - When `true`, bypasses driver initialization and PPL elevation, running the agent in standalone mode.
fn init_driver_and_ppl(skip_driver: bool) {
    if !skip_driver {
        if let Err(e) = pulsar::bootstrap::initialize() {
            log::error!("Bootstrap initialization failed: {}", e);
            std::process::exit(ERROR_SERVICE_DEPENDENCY_FAIL as i32);
        }
    } else {
        log::warn!("Running in standalone mode: driver initialization and PPL elevation skipped.");
    }
}

/// Initializes the telemetry ingestion channel, shared symbol resolver, and starts the event dispatcher worker pool.
///
/// Configures and attaches subscribers (e.g. [`DirectSyscallSink`]) to the event
/// dispatcher based on enabled features, and spawns the background worker threads.
///
/// # Arguments
///
/// * `enable_syscalls` - Whether to register the [`DirectSyscallSink`] for stack tracing and syscall anomaly detection.
/// * `enable_context` - Whether to enable kernel context providers.
///
/// # Returns
///
/// A tuple containing:
/// * The lock-free crossbeam sender [`Sender<EventRecord>`] used to ingest raw ETW events into the channel.
/// * The [`DispatcherHandle`] managing the background dispatcher worker pool.
fn setup_event_pipeline(
    enable_syscalls: bool,
    enable_context: bool,
) -> (Sender<EventRecord>, DispatcherHandle) {
    // Lock-free MPMC queue for high throughput across worker threads
    let (tx, rx) = crossbeam_channel::bounded::<EventRecord>(1_000_000);

    let mut dispatcher = EventDispatcher::new(rx);

    if enable_syscalls {
        log::info!("Feature enabled: Direct Syscall Detection Sink.");
        dispatcher.add_subscriber(Box::new(DirectSyscallSink::new()));
    } else {
        log::debug!("Feature disabled: Direct Syscall Detection Sink.");
    }

    if enable_context {
        log::info!("System Context Ingress Engine active (Automatic Process & Module Tracking).");
    } else {
        log::debug!("System Context Ingress tracking not requested.");
    }

    if !enable_syscalls && !enable_context {
        log::warn!(
            "No telemetry sinks or context modules registered. Running in passive collection mode."
        );
    }

    let dispatcher_handle = dispatcher.start();
    (tx, dispatcher_handle)
}

/// Builds and starts the NT Kernel Logger ETW trace session and spawns the real-time consumer thread.
///
/// Uses the [`SessionDirector`] to construct a tailored kernel session based on enabled flags,
/// starts kernel tracing, and launches the consumer thread to feed events into the ingestion channel.
///
/// # Arguments
///
/// * `enable_syscalls` - Whether to enable PerfInfo syscall tracing and stack walking.
/// * `enable_context` - Whether to enable process and image load kernel flags.
/// * `tx` - Sender channel for forwarding raw [`EventRecord`] payloads.
///
/// # Returns
///
/// `Ok((KernelSession, JoinHandle))` containing the active session handle and consumer thread handle,
/// or `Err(AppError)` if session creation fails.
///
/// # Errors
///
/// Returns an [`AppError`] if building or starting the kernel trace session fails.
fn start_kernel_session(
    enable_syscalls: bool,
    enable_context: bool,
    tx: Sender<EventRecord>,
) -> Result<(KernelSession, JoinHandle<Result<(), AppError>>), AppError> {
    log::debug!("Configuring NT Kernel Logger session properties...");
    let mut builder = KernelSessionBuilder::new();
    SessionDirector::construct_edr_session(&mut builder, enable_syscalls, enable_context);
    let mut kernel_session = builder.build()?;

    log::info!("Starting NT Kernel Logger real-time session...");
    kernel_session.start()?;

    log::debug!("Spawning real-time ETW trace consumer worker thread...");
    let consumer_handle = kernel_session.consume(tx)?;

    Ok((kernel_session, consumer_handle))
}

/// Installs a signal handler (Ctrl+C) and parks the main thread until shutdown is triggered.
///
/// Consumes 0.0% CPU while blocked using an efficient bounded crossbeam synchronization channel.
fn wait_for_shutdown() {
    let (shutdown_tx, shutdown_rx) = crossbeam_channel::bounded::<()>(1);

    ctrlc::set_handler(move || {
        log::info!("Shutdown signal received (Ctrl+C). Initiating graceful teardown...");
        let _ = shutdown_tx.send(());
    })
    .expect("Error setting Ctrl-C handler");

    // Block the main thread efficiently with zero CPU utilization
    let _ = shutdown_rx.recv();
}

/// Gracefully stops the active ETW session, unparks consumer threads, and drains the dispatcher queue.
///
/// # Arguments
///
/// * `kernel_session` - The active [`KernelSession`] to stop.
/// * `consumer_handle` - Join handle of the trace consumer thread.
/// * `dispatcher_handle` - Join handle of the background dispatcher worker pool.
fn teardown_session(
    mut kernel_session: KernelSession,
    consumer_handle: JoinHandle<Result<(), AppError>>,
    dispatcher_handle: DispatcherHandle,
) {
    log::info!("Stopping NT Kernel Logger session...");
    if let Err(e) = kernel_session.stop() {
        log::error!("Error stopping kernel ETW session: {}", e);
    }

    log::info!("Waiting for ETW consumer thread to exit...");
    if let Err(e) = consumer_handle.join() {
        log::error!("ETW consumer thread encountered an error: {:?}", e);
    }

    log::info!("Waiting for dispatcher worker threads to drain and complete...");
    if let Err(e) = dispatcher_handle.join() {
        log::error!("Dispatcher worker pool encountered an error: {:?}", e);
    }

    log::info!("Quasar EDR Engine teardown complete. Goodbye!");
}
