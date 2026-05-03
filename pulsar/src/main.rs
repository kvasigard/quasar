#![allow(dead_code)]

use std::sync::mpsc;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};

use pulsar::communications::kmdf;
use pulsar::helpers::symbol_resolver::SymbolResolver;
use pulsar::pipeline::Event;
use pulsar::pipeline::EventDispatcher;
use pulsar::sensors::etw::EtwSession;
use pulsar::sensors::etw::KernelSessionBuilder;
use pulsar::sensors::etw::director::SessionDirector;
use pulsar::sinks::direct_sys::DirectSyscallSink;

fn main() {
    // Initialize the standard 'log' crate using env_logger.
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    log::info!("Starting Singularity ETW Engine...");

    if let Err(e) = kmdf::request_ppl() {
        log::error!("Failed to get PPL priviledges: {}", e);
        return;
    }

    // Atomic flag to signal immediate shutdown across threads.
    let shutdown_flag = Arc::new(AtomicBool::new(false));

    // Establish the main inter-thread communication bus.
    let (tx, rx) = mpsc::sync_channel::<Event>(1_000_000);

    // Initialize the shared Symbol Resolver.
    // Since DbgHelp is not inherently thread-safe and we will have multiple
    // sinks requesting resolutions, we wrap it in an Arc<Mutex<>>.
    let shared_resolver = Arc::new(Mutex::new(SymbolResolver::new()));

    // Initialize the central event router.
    let mut dispatcher = EventDispatcher::new(rx);

    // Wire up Direct Syscall correlator/sink
    // We pass a clone of the Arc, giving the sink a thread-safe reference to the resolver.
    dispatcher.add_subscriber(Box::new(DirectSyscallSink::new(Arc::clone(
        &shared_resolver,
    ))));

    // Launch the dispatcher in a background thread.
    let dispatcher_handle = dispatcher.start(Arc::clone(&shutdown_flag));

    // Define the underlying trace session properties.
    let mut session_builder = KernelSessionBuilder::new();
    SessionDirector::construct_syscall_monitor(&mut session_builder);

    let mut kernel_session = match session_builder.build() {
        Ok(session) => session,
        Err(e) => {
            log::error!("Failed to build kernel session: {}", e);
            return;
        }
    };

    // Request the Windows OS to spin up the NT Kernel Logger.
    if let Err(e) = kernel_session.start() {
        log::error!("Failed to start ETW session: {}", e);
        return;
    }

    // Spawn the background thread responsible for blocking on `ProcessTrace`.
    let consumer_handle = match kernel_session.consume(tx) {
        Ok(handle) => handle,
        Err(e) => {
            log::error!("Failed to spawn consumer thread: {}", e);
            let _ = kernel_session.stop();
            return;
        }
    };

    log::info!("System is running and capturing events. Press Ctrl+C to safely stop...");

    // Set up a channel to block the main thread until an OS interruption occurs.
    let (shutdown_tx, shutdown_rx) = std::sync::mpsc::channel();

    let ctrlc_flag = Arc::clone(&shutdown_flag);
    ctrlc::set_handler(move || {
        log::info!("Termination signal detected. Signaling application to stop...");
        ctrlc_flag.store(true, Ordering::SeqCst);
        let _ = shutdown_tx.send(());
    })
    .expect("Error setting Ctrl-C handler");

    // Block the main thread indefinitely until the Ctrl+C handler sends a message.
    let _ = shutdown_rx.recv();

    log::info!("Initiating graceful shutdown sequence...");

    if let Err(e) = kernel_session.stop() {
        log::error!("Failed to stop session: {}", e);
    }

    if let Err(e) = consumer_handle.join() {
        log::error!("Consumer thread panicked during execution: {:?}", e);
    }

    if let Err(e) = dispatcher_handle.join() {
        log::error!("Dispatcher thread panicked during execution: {:?}", e);
    }

    log::info!("Graceful shutdown complete. All resources freed successfully.");
}
