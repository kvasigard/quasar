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
    #[arg(long, help = "Disable ETW kernel process and image load event tracing")]
    pub disable_context: bool,

    /// Skip Singularity driver installation, loading, and PPL elevation (standalone ETW mode).
    #[arg(
        long,
        help = "Skip driver service loading and PPL elevation (standalone ETW mode)"
    )]
    pub skip_driver: bool,

    /// Custom directory containing Rhai detection and suppression rules (defaults to './rules').
    #[arg(long, default_value = "./rules", help = "Path to Rhai rules directory")]
    pub rules_dir: std::path::PathBuf,

    /// Disable Rhai rule evaluation and use raw fallback heuristics.
    #[arg(long, help = "Disable Rhai dynamic rule evaluation engine")]
    pub disable_rules: bool,
}

/// Handles the `--uninstall` CLI flag by requesting SCM to stop and delete the driver service.
fn handle_uninstall() -> Result<(), AppError> {
    log::info!("Uninstall option detected. Initiating Singularity driver teardown...");
    pulsar::drivers::scm::unload_driver()?;
    log::info!("Singularity driver successfully stopped and unregistered.");
    Ok(())
}

/// Orchestrates pre-flight driver installation, SCM service start, and PPL-Antimalware elevation.
fn init_driver_and_ppl(
    skip_driver: bool,
) -> Result<Option<Arc<pulsar::drivers::kmdf::Singularity>>, AppError> {
    if !skip_driver {
        let client = pulsar::bootstrap::initialize()?;
        Ok(Some(Arc::new(client)))
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
    rule_engine: Option<Arc<pulsar::rules::RuleEngine>>,
    shutdown_flag: Arc<AtomicBool>,
) -> (mpsc::SyncSender<EventRecord>, JoinHandle<()>) {
    // Bound the channel queue to 50,000 items to prevent unbounded memory allocation under heavy telemetry bursts.
    let (tx, rx) = mpsc::sync_channel::<EventRecord>(50_000);

    let mut dispatcher = EventDispatcher::new(rx);
    if let Some(drx) = driver_rx {
        dispatcher = dispatcher.with_driver_receiver(drx);
    }

    // Register analytical sinks
    dispatcher.add_listener(Box::new(pulsar::sinks::ProcessContextSink::new(
        rule_engine.clone(),
    )));
    dispatcher.add_listener(Box::new(pulsar::sinks::DetectionSink::new(
        rule_engine,
        Arc::new(pulsar::alerts::ConsoleEmitter::new()),
    )));

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
    rule_watcher_handle: Option<JoinHandle<()>>,
) {
    log::info!("Initiating graceful shutdown sequence...");

    if let Err(e) = kernel_session.stop() {
        log::error!("Failed to stop ETW kernel session: {}", e);
    }

    match consumer_handle.join() {
        Ok(Ok(())) => {}
        Ok(Err(etw_err)) => {
            log::error!("ETW consumer thread exited with error: {etw_err}");
        }
        Err(e) => {
            log::error!("Consumer thread panicked during execution: {:?}", e);
        }
    }

    if let Some(sensor_handle) = driver_sensor_handle
        && let Err(e) = sensor_handle.join()
    {
        log::error!("Driver sensor thread panicked during execution: {:?}", e);
    }

    if let Err(e) = dispatcher_handle.join() {
        log::error!("Dispatcher thread panicked during execution: {:?}", e);
    }

    if let Some(watcher_handle) = rule_watcher_handle
        && let Err(e) = watcher_handle.join()
    {
        log::error!("Rule watcher thread panicked during execution: {:?}", e);
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

    // Initialize Rhai Rule Engine
    let rule_engine = if !cli.disable_rules {
        log::info!(
            "Initializing Rhai Scripting Rule Engine from '{}'...",
            cli.rules_dir.display()
        );
        match pulsar::rules::RuleEngine::load(&cli.rules_dir) {
            Ok(engine) => {
                log::info!(
                    "Rhai Rule Engine initialized with {} active rules.",
                    engine.rule_count()
                );
                Some(Arc::new(engine))
            }
            Err(e) => {
                log::error!(
                    "Failed to initialize Rhai Rule Engine from '{}': {e}",
                    cli.rules_dir.display()
                );
                return Err(e.into());
            }
        }
    } else {
        log::warn!("Rhai Rule Engine disabled by CLI flag (--disable-rules).");
        None
    };

    // Spawn background rule watcher for hot-reloading
    let rule_watcher_handle = if let Some(ref engine) = rule_engine {
        match engine.spawn_watcher(cli.rules_dir.clone(), Arc::clone(&shutdown_flag)) {
            Ok(handle) => Some(handle),
            Err(e) => {
                log::warn!("Failed to start dynamic rule watcher: {e}");
                None
            }
        }
    } else {
        None
    };

    // Initialize driver telemetry sensor if driver is present
    let (driver_rx, driver_sensor_handle) = if let Some(ref driver) = driver_client {
        log::info!("Initializing Singularity driver telemetry sensor (Per-CPU ring buffer)...");
        let sensor = match DriverSensor::initialize_shared(Arc::clone(driver)) {
            Ok(s) => s,
            Err(e) => {
                shutdown_flag.store(true, Ordering::SeqCst);
                if let Some(watcher_handle) = rule_watcher_handle {
                    let _ = watcher_handle.join();
                }
                return Err(e.into());
            }
        };
        let (dtx, drx) = mpsc::sync_channel::<Event>(4_096);
        let flag = Arc::clone(&shutdown_flag);
        let handle = sensor.start(flag, move |event| {
            let _ = dtx.try_send(event);
        });
        (Some(drx), Some(handle))
    } else {
        (None, None)
    };

    // Setup event bus and dispatching pipeline
    let enable_syscalls = !cli.disable_syscalls;
    let enable_context = !cli.disable_context;

    let (tx, dispatcher_handle) = setup_event_pipeline(
        enable_syscalls,
        enable_context,
        driver_rx,
        rule_engine,
        Arc::clone(&shutdown_flag),
    );

    // Launch NT Kernel Logger ETW trace session; if it fails, signal shutdown and join background threads
    // before dropping `driver_client` so the sensor never reads unmapped MDL pages.
    let (kernel_session, consumer_handle) =
        match start_kernel_session(enable_syscalls, enable_context, tx) {
            Ok(pair) => pair,
            Err(err) => {
                shutdown_flag.store(true, Ordering::SeqCst);
                if let Some(sensor_handle) = driver_sensor_handle {
                    let _ = sensor_handle.join();
                }
                let _ = dispatcher_handle.join();
                if let Some(watcher_handle) = rule_watcher_handle {
                    let _ = watcher_handle.join();
                }
                return Err(err);
            }
        };

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
        rule_watcher_handle,
    );

    // Dropping driver_client triggers EvtFileCleanup in driver after all threads have joined
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
