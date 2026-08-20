//! Structured execution timing, performance diagnostics, and bottleneck profiling subsystem.
//!
//! Integrates the Tokio `tracing` framework with span-level execution timing,
//! console/file formatting, log bridging, and Chrome Trace (`chrome://tracing` / Perfetto) export.

use std::fs::File;
use std::path::Path;
use tracing_chrome::FlushGuard;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{fmt, EnvFilter, Layer};

use crate::cli::LogMode;

/// Handle keeping active profilers alive until application shutdown.
pub struct ProfilingGuard {
    _chrome_guard: Option<FlushGuard>,
}

/// Initializes structured logging, span tracing, and optional Chrome Trace profiling.
///
/// # Arguments
///
/// * `log_mode` - Optional verbosity level requested via CLI.
/// * `log_file` - Optional file path where formatted logs should be written.
/// * `chrome_trace_path` - Optional file path to output Chrome DevTools flame chart JSON data.
///
/// # Returns
///
/// A [`ProfilingGuard`] that flushes all trace buffers upon drop.
pub fn init_profiling(
    log_mode: Option<LogMode>,
    log_file: Option<impl AsRef<Path>>,
    chrome_trace_path: Option<impl AsRef<Path>>,
) -> ProfilingGuard {
    // 1. Determine default filter
    let default_level = log_mode
        .map(tracing_subscriber::filter::LevelFilter::from)
        .unwrap_or(tracing_subscriber::filter::LevelFilter::INFO);

    let env_filter = EnvFilter::builder()
        .with_default_directive(default_level.into())
        .from_env_lossy();

    // 2. Set up Chrome DevTools Profiling Layer (if requested)
    let (chrome_layer, chrome_guard) = if let Some(path) = chrome_trace_path {
        let (layer, guard) = tracing_chrome::ChromeLayerBuilder::new()
            .file(path.as_ref())
            .build();
        (Some(layer), Some(guard))
    } else {
        (None, None)
    };

    let registry = tracing_subscriber::registry().with(env_filter);
    let chrome_boxed = chrome_layer.map(|l| l.boxed());

    // 3. Set up Formatted Output Layer (Console or File)
    if let Some(file_path) = log_file {
        let file = File::create(file_path).expect("Failed to create log output file");
        let fmt_layer = fmt::layer()
            .with_ansi(false)
            .with_thread_names(true)
            .with_target(true)
            .with_writer(file)
            .boxed();

        let _ = registry.with(fmt_layer).with(chrome_boxed).try_init();
    } else {
        let fmt_layer = fmt::layer()
            .with_ansi(true)
            .with_thread_names(true)
            .with_target(true)
            .with_writer(std::io::stdout)
            .boxed();

        let _ = registry.with(fmt_layer).with(chrome_boxed).try_init();
    }

    ProfilingGuard {
        _chrome_guard: chrome_guard,
    }
}
