//! Pulsar EDR Agent - Main entry point and orchestration.

use std::sync::mpsc;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::thread::JoinHandle;

use clap::Parser;
use pulsar::error::AppError;
use pulsar::helpers::symbol_resolver::SymbolResolver;
use pulsar::pipeline::{Event, EventDispatcher};
use pulsar::sensors::etw::director::SessionDirector;
use pulsar::sensors::etw::{EtwSession, KernelSession, KernelSessionBuilder};
use pulsar::sinks::direct_sys::DirectSyscallSink;
use windows_sys::Win32::Foundation::ERROR_SERVICE_DEPENDENCY_FAIL;

/// Pulsar Endpoint Detection and Response (EDR) Telemetry Agent.
#[derive(Parser, Debug)]
#[command(
    name = "pulsar",
    author = "Quasar Team",
    version,
    about = "Lightweight Windows Endpoint Detection and Response (EDR) agent",
    long_about = "Pulsar is the user-mode agent for the Quasar EDR engine. It manages driver lifecycle, \
                  spins up real-time NT Kernel Logger ETW sessions, and routes telemetry through \
                  analytical sinks for behavioral detection and context tracking."
)]
pub struct Cli {
    /// Stop and uninstall the Singularity kernel driver service from SCM and exit.
    #[arg(short, long)]
    pub uninstall: bool,

    /// Disable Direct Syscall anomaly detection and kernel stack tracing.
    #[arg(
        long,
        help = "Disable direct syscall anomaly detection and stack tracing"
    )]
    pub disable_syscalls: bool,

    /// Disable system process tree and module mapping context tracking.
    #[arg(
        long,
        help = "Disable system process tree and module mapping context tracking"
    )]
    pub disable_context: bool,

    /// Skip Singularity driver installation, loading, and PPL elevation (standalone ETW mode).
    #[arg(
        long,
        help = "Skip driver service loading and PPL elevation (standalone ETW mode)"
    )]
    pub skip_driver: bool,
}

/// Handles the `--uninstall` CLI flag by requesting SCM to stop and delete the driver service.
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
fn setup_event_pipeline(
    enable_syscalls: bool,
    enable_context: bool,
    shutdown_flag: Arc<AtomicBool>,
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
    } else {
        log::debug!("Feature disabled: System Context Sink.");
    }

    if !enable_syscalls && !enable_context {
        log::warn!(
            "No detection or context sinks were enabled. Running in pass-through ingestion mode."
        );
    }

    let dispatcher_handle = dispatcher.start(shutdown_flag);
    (tx, dispatcher_handle)
}

/// Configures and starts the NT Kernel Logger ETW session, returning the active session and consumer handle.
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

/// Registers the Ctrl+C signal handler and blocks the main thread until interruption is received.
fn wait_for_shutdown(shutdown_flag: Arc<AtomicBool>) {
    let (shutdown_tx, shutdown_rx) = mpsc::channel();
    let ctrlc_flag = Arc::clone(&shutdown_flag);

    ctrlc::set_handler(move || {
        log::info!("Termination signal detected. Signaling application to stop...");
        ctrlc_flag.store(true, Ordering::SeqCst);
        let _ = shutdown_tx.send(());
    })
    .expect("Error setting Ctrl-C handler");

    let _ = shutdown_rx.recv();
}

/// Gracefully stops the ETW kernel trace session and joins background worker threads.
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

fn main() {
    // Initialize logging from environment (supports dynamic RUST_LOG configuration, defaulting to info)
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let cli = Cli::parse();
    log::debug!("Parsed CLI configuration: {:?}", cli);

    if cli.uninstall {
        handle_uninstall();
    }

    log::info!("Starting Quasar EDR Engine (Pulsar)...");

    // Phase 1: Initialize driver and request PPL elevation
    init_driver_and_ppl(cli.skip_driver);

    let shutdown_flag = Arc::new(AtomicBool::new(false));

    // Phase 2: Setup event bus and dispatching pipeline
    let enable_syscalls = !cli.disable_syscalls;
    let enable_context = !cli.disable_context;

    let (tx, dispatcher_handle) =
        setup_event_pipeline(enable_syscalls, enable_context, Arc::clone(&shutdown_flag));

    // Phase 3: Build and start NT Kernel Logger ETW session
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

    // Phase 4: Wait for user termination signal
    wait_for_shutdown(shutdown_flag);

    // Phase 5: Teardown session and join worker threads
    teardown_session(kernel_session, consumer_handle, dispatcher_handle);
}
