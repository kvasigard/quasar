use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use clap::Parser;
use pulsar::cli::Cli;
use pulsar::error::AppError;
use pulsar::helpers::symbol_resolver::SymbolResolver;
use pulsar::pipeline::{Event, EventDispatcher};
use pulsar::sensors::etw::director::SessionDirector;
use pulsar::sensors::etw::{EtwSession, KernelSession, KernelSessionBuilder};
use pulsar::sinks::{direct_sys::DirectSyscallSink, system_context::SystemContextSink};
use windows_sys::Win32::Foundation::ERROR_SERVICE_DEPENDENCY_FAIL;

/// Application entry point for the Pulsar EDR agent.
///
/// Parses command-line arguments, orchestrates driver bootstrap, configures the event pipeline
/// and ETW session, and manages execution lifecycle until termination.
fn main() {
    let cli = Cli::parse();
    init_logger(&cli);

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

    // TODO: Currently the setup_event_pipline does not follow the Open-Closed
    // principle; everytime a new functionality is added we need to change the
    // funtion signature. In the future consider using a global configuration.
    // To be future-prove that configuration shall be able to change the EDR
    // behaviour at runtime.
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

/// Initializes the telemetry ingestion channel, shared symbol resolver, and starts the event dispatcher thread.
///
/// Configures and attaches subscribers (e.g. [`DirectSyscallSink`], [`SystemContextSink`]) to the event
/// dispatcher based on enabled features, and spawns the background worker thread.
///
/// # Arguments
///
/// * `enable_syscalls` - Whether to register the [`DirectSyscallSink`] for stack tracing and syscall anomaly detection.
/// * `enable_context` - Whether to register the [`SystemContextSink`] for process and module tracking.
///
/// # Returns
///
/// A tuple containing:
/// * The synchronous sender [`mpsc::SyncSender<Event>`] used to ingest ETW events into the channel.
/// * The [`JoinHandle<()>`] for the background dispatcher worker thread.
fn setup_event_pipeline(
    enable_syscalls: bool,
    enable_context: bool,
) -> (mpsc::SyncSender<Event>, JoinHandle<()>) {
    // Inter-thread ring-buffer queue for high throughput
    let (tx, rx) = mpsc::sync_channel::<Event>(1_000_000);

    let shared_resolver = Arc::new(Mutex::new(SymbolResolver::new()));
    let mut dispatcher = EventDispatcher::new(rx);

    if enable_syscalls {
        log::info!("Feature enabled: Direct Syscall Detection Sink.");
        dispatcher.add_subscriber(Box::new(DirectSyscallSink::new(Arc::clone(
            &shared_resolver,
        ))));
    } else {
        log::debug!("Feature disabled: Direct Syscall Detection Sink.");
    }

    if enable_context {
        log::info!("Feature enabled: System Context Sink (Process & Module Tracking).");
        dispatcher.add_subscriber(Box::new(SystemContextSink));
    } else {
        log::debug!("Feature disabled: System Context Sink.");
    }

    if !enable_syscalls && !enable_context {
        log::warn!(
            "No detection or context sinks were enabled. Running in pass-through ingestion mode."
        );
    }

    let dispatcher_handle = dispatcher.start();
    (tx, dispatcher_handle)
}

/// Configures and starts the NT Kernel Logger ETW session, returning the active session and consumer handle.
///
/// Constructs the ETW session according to the active sink configurations, starts trace collection,
/// and begins consuming events asynchronously via a background thread.
///
/// # Arguments
///
/// * `enable_syscalls` - Enables ETW kernel providers required for syscall tracing.
/// * `enable_context` - Enables ETW kernel providers required for process/image context tracking.
/// * `tx` - Ingestion channel sender passed to the ETW consumer to forward events into the pipeline.
///
/// # Returns
///
/// A tuple containing the active [`KernelSession`] and the consumer thread [`JoinHandle`].
///
/// # Errors
///
/// Returns an [`AppError`] if session building, starting, or consumer attachment fails.
fn start_kernel_session(
    enable_syscalls: bool,
    enable_context: bool,
    tx: mpsc::SyncSender<Event>,
) -> Result<(KernelSession, JoinHandle<Result<(), AppError>>), AppError> {
    let mut session_builder = KernelSessionBuilder::new();
    SessionDirector::construct_edr_session(&mut session_builder, enable_syscalls, enable_context);

    let mut kernel_session = session_builder.build()?;

    kernel_session.start()?;

    let consumer_handle = match kernel_session.consume(tx) {
        Ok(handle) => handle,
        Err(e) => {
            let _ = kernel_session.stop();
            return Err(e);
        }
    };

    Ok((kernel_session, consumer_handle))
}

/// Registers the Ctrl+C signal handler and blocks the main thread until an interruption signal is received.
///
/// # Panics
///
/// Panics if setting the Ctrl+C signal handler fails.
fn wait_for_shutdown() {
    let (shutdown_tx, shutdown_rx) = mpsc::channel();

    ctrlc::set_handler(move || {
        log::info!("Termination signal detected. Signaling application to stop...");
        let _ = shutdown_tx.send(());
    })
    .expect("Error setting Ctrl-C handler");

    // Pure OS-level wait, 0% CPU usage
    let _ = shutdown_rx.recv();
}

/// Gracefully stops the ETW kernel trace session and joins background worker threads.
///
/// Stops event tracing on the active [`KernelSession`], waits for the ETW consumer thread
/// to exit, and waits for the dispatcher thread to complete event processing and shut down.
///
/// # Arguments
///
/// * `kernel_session` - The active ETW kernel session to stop.
/// * `consumer_handle` - Handle to the ETW consumer background thread to join.
/// * `dispatcher_handle` - Handle to the event dispatcher background thread to join.
fn teardown_session(
    mut kernel_session: KernelSession,
    consumer_handle: JoinHandle<Result<(), AppError>>,
    dispatcher_handle: JoinHandle<()>,
) {
    log::info!("Initiating graceful shutdown sequence...");

    if let Err(e) = kernel_session.stop() {
        log::error!("Failed to stop ETW kernel session: {}", e);
    }

    if let Err(e) = consumer_handle.join() {
        log::error!("Consumer thread panicked during execution: {:?}", e);
    }

    if let Err(e) = dispatcher_handle.join() {
        log::error!("Dispatcher thread panicked during execution: {:?}", e);
    }

    log::info!("Graceful shutdown complete. All resources freed successfully.");
}

/// Initializes the `env_logger` subsystem according to command-line parameters and environment variables.
///
/// If `--log-file` is provided, redirects log output to the target file in append mode.
/// Otherwise, default stderr/stdout console logging is used. If `--log-mode` is supplied,
/// applies the specified [`log::LevelFilter`], falling back to the `RUST_LOG` environment
/// variable or `"info"` by default.
///
/// # Arguments
///
/// * `cli` - Parsed command-line arguments.
fn init_logger(cli: &Cli) {
    let mut builder =
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"));

    if let Some(log_mode) = cli.log_mode {
        builder.filter_level(log_mode.into());
    }

    if let Some(ref log_path) = cli.log_file {
        match std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_path)
        {
            Ok(file) => {
                builder.target(env_logger::Target::Pipe(Box::new(file)));
            }
            Err(e) => {
                eprintln!("Failed to open log file '{}': {}", log_path.display(), e);
                std::process::exit(1);
            }
        }
    }

    builder.init();
}
