//! Pulsar EDR Agent - Main entry point and orchestration.

use std::sync::mpsc;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread::JoinHandle;

use clap::Parser;
use pulsar::error::AppError;
use pulsar::pipeline::{Event, EventDispatcher};
use pulsar::sensors::driver::DriverSensor;
use pulsar::sensors::etw::director::SessionDirector;
use pulsar::sensors::etw::{
    EtwError, EtwSession, EventRecord, KernelSession, KernelSessionBuilder,
};
use pulsar::sinks::LsassAccessSink;

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

    /// Disable ETW kernel process and image load event tracing.
    #[arg(
        long,
        help = "Disable ETW kernel process and image load event tracing"
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
fn handle_uninstall() -> Result<(), AppError> {
    log::info!("Uninstall option detected. Initiating Singularity driver teardown...");
    pulsar::drivers::scm::unload_driver()?;
    log::info!("Singularity driver successfully stopped and unregistered.");
    Ok(())
}

/// Orchestrates pre-flight driver installation, SCM service start, and PPL-Antimalware elevation.
fn init_driver_and_ppl(skip_driver: bool) -> Result<Option<pulsar::drivers::kmdf::Singularity>, AppError> {
    if !skip_driver {
        let client = pulsar::bootstrap::initialize()?;
        Ok(Some(client))
    } else {
        log::warn!("Running in standalone mode: driver initialization and PPL elevation skipped.");
        Ok(None)
    }
}

/// Initializes the telemetry ingestion channel and starts the event dispatcher thread.
fn setup_event_pipeline(
    enable_syscalls: bool,
    enable_context: bool,
    driver_rx: Option<mpsc::Receiver<Event>>,
    shutdown_flag: Arc<AtomicBool>,
) -> (mpsc::SyncSender<EventRecord>, JoinHandle<()>) {
    // Bound the channel queue to 50,000 items to prevent unbounded memory allocation under heavy telemetry bursts.
    let (tx, rx) = mpsc::sync_channel::<EventRecord>(50_000);

    let mut dispatcher = EventDispatcher::new(rx);
    if let Some(drx) = driver_rx {
        dispatcher = dispatcher.with_driver_receiver(drx);
    }

    // Register analytical sinks
    dispatcher.add_listener(Box::new(LsassAccessSink::new()));

    if enable_syscalls {
        log::info!("Feature enabled: Syscall Tracing.");
    } else {
        log::debug!("Feature disabled: Syscall Tracing.");
    }

    if enable_context {
        log::info!("Feature enabled: Process & System Context Tracing.");
    } else {
        log::debug!("Feature disabled: Process & System Context Tracing.");
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
    tx: mpsc::SyncSender<EventRecord>,
) -> Result<(KernelSession, JoinHandle<Result<(), EtwError>>), AppError> {
    let mut session_builder = KernelSessionBuilder::new();
    SessionDirector::construct_edr_session(&mut session_builder, enable_syscalls, enable_context);

    let mut kernel_session = session_builder.build()?;

    kernel_session.start()?;

    let consumer_handle = match kernel_session.consume(tx) {
        Ok(handle) => handle,
        Err(e) => {
            let _ = kernel_session.stop();
            return Err(e.into());
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

/// Gracefully stops the ETW kernel trace session, driver sensor, and joins background worker threads.
fn teardown_session(
    mut kernel_session: KernelSession,
    consumer_handle: JoinHandle<Result<(), EtwError>>,
    dispatcher_handle: JoinHandle<()>,
    driver_sensor_handle: Option<JoinHandle<()>>,
) {
    log::info!("Initiating graceful shutdown sequence...");

    if let Err(e) = kernel_session.stop() {
        log::error!("Failed to stop ETW kernel session: {}", e);
    }

    if let Err(e) = consumer_handle.join() {
        log::error!("Consumer thread panicked during execution: {:?}", e);
    }

    if let Some(sensor_handle) = driver_sensor_handle
        && let Err(e) = sensor_handle.join()
    {
        log::error!("Driver sensor thread panicked during execution: {:?}", e);
    }

    if let Err(e) = dispatcher_handle.join() {
        log::error!("Dispatcher thread panicked during execution: {:?}", e);
    }

    log::info!("Graceful shutdown complete. All resources freed successfully.");
}

fn run(cli: Cli) -> Result<(), AppError> {
    if cli.uninstall {
        return handle_uninstall();
    }

    log::info!("Starting Quasar EDR Engine (Pulsar)...");

    let shutdown_flag = Arc::new(AtomicBool::new(false));

    // Initialize driver service and elevate to PPL
    let driver_client = init_driver_and_ppl(cli.skip_driver)?;

    // Initialize driver telemetry sensor if driver is present
    let (driver_rx, driver_sensor_handle) = if let Some(ref driver) = driver_client {
        log::info!("Initializing Singularity driver telemetry sensor (Per-CPU ring buffer)...");
        let sensor = DriverSensor::initialize(driver)?;
        let (dtx, drx) = mpsc::channel();
        let flag = Arc::clone(&shutdown_flag);
        let handle = sensor.start(flag, move |event| {
            let _ = dtx.send(event);
        });
        (Some(drx), Some(handle))
    } else {
        (None, None)
    };

    // Setup event bus and dispatching pipeline
    let enable_syscalls = !cli.disable_syscalls;
    let enable_context = !cli.disable_context;

    let (tx, dispatcher_handle) =
        setup_event_pipeline(enable_syscalls, enable_context, driver_rx, Arc::clone(&shutdown_flag));

    // Launch NT Kernel Logger ETW trace session
    let (kernel_session, consumer_handle) =
        start_kernel_session(enable_syscalls, enable_context, tx)?;

    log::info!(
        "Quasar EDR Engine is active and capturing telemetry. Press Ctrl+C to safely stop..."
    );

    // Wait for user termination signal
    wait_for_shutdown(shutdown_flag);

    // Teardown trace sessions and background workers
    teardown_session(
        kernel_session,
        consumer_handle,
        dispatcher_handle,
        driver_sensor_handle,
    );

    // Dropping driver_client triggers EvtFileCleanup in driver
    drop(driver_client);

    Ok(())
}

fn main() -> std::process::ExitCode {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let cli = Cli::parse();
    log::debug!("Parsed CLI configuration: {:?}", cli);

    if let Err(e) = run(cli) {
        log::error!("Application error encountered: {e}");

        let mut source = std::error::Error::source(&e);
        while let Some(cause) = source {
            log::error!("  Caused by: {cause}");
            source = cause.source();
        }

        return std::process::ExitCode::FAILURE;
    }

    std::process::ExitCode::SUCCESS
}
