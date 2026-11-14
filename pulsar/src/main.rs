//! Pulsar EDR Agent — Main entry point, CLI parsing, and runtime lifecycle orchestration.
//!
//! # Startup & Shutdown Orchestration
//!
//! 1. **Driver & PPL Bootstrap (`init_driver_and_ppl`):** Installs/starts the Singularity KMDF
//!    driver via SCM and elevates the user-mode agent process to `PPL-Antimalware` (unless
//!    `--skip-driver` is passed).
//! 2. **Rule Engine & Hot-Reload (`RuleEngine`):** Compiles `.rhai` rules from `--rules-dir` and
//!    spawns a filesystem watcher thread.
//! 3. **Priority-Split Pipeline (`setup_event_pipeline`):** Allocates the high-priority `state_tx`
//!    (`16,384` capacity) and standard `telemetry_tx` (`50,000` capacity) channels, registers
//!    `ProcessContextSink` before `DetectionSink` on [`EventDispatcher`], and spawns the
//!    `pulsar-dispatcher` worker thread.
//! 4. **System Logger V2 Session (`start_kernel_session`):** Configures [`KernelSessionBuilder`]
//!    via [`SessionDirector`] (with syscall tracing **disabled by default** unless `--enable-syscalls`
//!    is passed), starts the kernel trace session, and spawns the zero-copy consumer worker via
//!    [`EtwSession::consume_with_router`].
//! 5. **Deterministic Teardown (`teardown_session`):** On `Ctrl+C`, stops the ETW session in the
//!    kernel (`ControlTraceW`), closes the `OpenTraceW` handle via [`ConsumerHandle::stop_and_join`],
//!    logs final [`ConsumerMetricsSnapshot`](pulsar::sensors::etw::ConsumerMetricsSnapshot) counters,
//!    and joins all worker threads.

use std::sync::mpsc;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread::JoinHandle;

use clap::Parser;
use pulsar::error::AppError;
use pulsar::pipeline::{Event, EventDispatcher, PipelineEventRouter, TelemetryEnvelope};
use pulsar::sensors::driver::DriverSensor;
use pulsar::sensors::etw::director::{KernelTraceConfig, SessionDirector};
use pulsar::sensors::etw::{ConsumerHandle, EtwSession, KernelSession, KernelSessionBuilder};

/// Command-line configuration for the Pulsar Endpoint Detection and Response (EDR) agent.
#[derive(Parser, Debug)]
#[command(
    name = "pulsar",
    author = "Quasar Team",
    version,
    about = "Lightweight Windows Endpoint Detection and Response (EDR) agent",
    long_about = "Pulsar is the user-mode agent for the Quasar EDR engine. It manages driver lifecycle, \
                  spins up real-time System Logger V2 ETW sessions, and routes telemetry through \
                  analytical sinks for behavioral detection and context tracking."
)]
pub struct Cli {
    /// Stop and uninstall the Singularity kernel driver service from SCM and exit.
    #[arg(short, long)]
    pub uninstall: bool,

    /// Explicitly enable Direct Syscall anomaly detection and kernel stack tracing (disabled by default).
    #[arg(
        long,
        help = "Enable direct syscall anomaly detection and kernel stack tracing (disabled by default)"
    )]
    pub enable_syscalls: bool,

    /// Backwards-compatible hidden flag to force-disable syscall tracing.
    #[arg(long, hide = true)]
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

    /// Custom directory containing Rhai detection and suppression rules (defaults to `./rules`).
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

/// Initializes the priority-split telemetry ingestion channels, registers context and detection
/// sinks, and spawns the background [`EventDispatcher`] worker thread.
fn setup_event_pipeline(
    enable_syscalls: bool,
    enable_context: bool,
    driver_rx: Option<mpsc::Receiver<Event>>,
    rule_engine: Option<Arc<pulsar::rules::RuleEngine>>,
    shutdown_flag: Arc<AtomicBool>,
) -> (PipelineEventRouter, JoinHandle<()>) {
    // Dedicated high-priority channel for process/image/thread state updates, separated from
    // the high-volume telemetry channel so process creation events are never starved.
    let (state_tx, state_rx) = mpsc::sync_channel::<Event>(16_384);
    let (telemetry_tx, telemetry_rx) = mpsc::sync_channel::<TelemetryEnvelope>(50_000);

    let mut dispatcher = EventDispatcher::with_priority_channels(state_rx, telemetry_rx);
    if let Some(drx) = driver_rx {
        dispatcher = dispatcher.with_driver_receiver(drx);
    }

    // Register `ProcessContextSink` BEFORE `DetectionSink` so in-memory process state is
    // updated prior to rule evaluation for every dispatched event.
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
        log::debug!("Feature disabled (default): Syscall Tracing.");
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
    let router = PipelineEventRouter::new(state_tx, telemetry_tx);
    (router, dispatcher_handle)
}

/// Configures and starts the System Logger V2 ETW session, returning the active [`KernelSession`]
/// and its background [`ConsumerHandle`].
fn start_kernel_session(
    enable_syscalls: bool,
    enable_context: bool,
    router: PipelineEventRouter,
) -> Result<(KernelSession, ConsumerHandle), AppError> {
    let mut session_builder = KernelSessionBuilder::new();
    let config = KernelTraceConfig::default()
        .with_syscalls(enable_syscalls)
        .with_context(enable_context);
    SessionDirector::construct_kernel_session_with_config(&mut session_builder, config);

    let mut kernel_session = session_builder.build()?;

    kernel_session.start()?;

    let consumer_handle = match kernel_session.consume_with_router(router) {
        Ok(handle) => handle,
        Err(e) => {
            let _ = kernel_session.stop();
            return Err(e.into());
        }
    };

    Ok((kernel_session, consumer_handle))
}

/// Registers the `Ctrl+C` signal handler and blocks the main thread until an interrupt signal arrives.
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

/// Gracefully stops the ETW kernel trace session, closes the consumer trace handle, logs
/// telemetry health metrics, and joins all background worker threads.
fn teardown_session(
    mut kernel_session: KernelSession,
    consumer_handle: ConsumerHandle,
    dispatcher_handle: JoinHandle<()>,
    driver_sensor_handle: Option<JoinHandle<()>>,
    rule_watcher_handle: Option<JoinHandle<()>>,
) {
    log::info!("Initiating graceful shutdown sequence...");

    // 1. Stop the kernel trace session first (`ControlTraceW(..., EVENT_TRACE_CONTROL_STOP)`)
    //    so the OS flushes any partial buffers and stops producing new events.
    if let Err(e) = kernel_session.stop() {
        log::error!("Failed to stop ETW kernel session: {}", e);
    }

    // 2. Unblock `ProcessTrace` via `CloseTrace`, join the consumer thread, and log final metrics.
    if let Err(etw_err) = consumer_handle.stop_and_join() {
        log::error!("ETW consumer thread exited with error: {etw_err}");
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

    // Syscall events are OFF by default unless explicitly enabled via `--enable-syscalls`
    let enable_syscalls = cli.enable_syscalls && !cli.disable_syscalls;
    let enable_context = !cli.disable_context;

    let (router, dispatcher_handle) = setup_event_pipeline(
        enable_syscalls,
        enable_context,
        driver_rx,
        rule_engine,
        Arc::clone(&shutdown_flag),
    );

    let (kernel_session, consumer_handle) =
        match start_kernel_session(enable_syscalls, enable_context, router) {
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

    wait_for_shutdown(shutdown_flag);

    let final_metrics = Arc::clone(consumer_handle.metrics());
    teardown_session(
        kernel_session,
        consumer_handle,
        dispatcher_handle,
        driver_sensor_handle,
        rule_watcher_handle,
    );
    let snap = final_metrics.snapshot();
    log::info!(
        "ETW consumer metrics: received={}, dispatched={}, filtered_out={}, dropped_full={}, parse_errors={}, buffers={}",
        snap.events_received,
        snap.events_dispatched,
        snap.events_filtered_out,
        snap.events_dropped_channel_full,
        snap.parse_errors,
        snap.buffers_processed
    );

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
