//! Command-line interface definition and argument parsing for Pulsar.

use std::path::PathBuf;
use clap::Parser;

/// Log level filter modes supported by the agent.
#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogMode {
    /// Disable all logging output.
    Off,
    /// Log error events only.
    Error,
    /// Log warning and error events.
    Warn,
    /// Log informational, warning, and error events (default).
    Info,
    /// Log detailed debug output along with informational messages.
    Debug,
    /// Log verbose trace output including internal state transitions.
    Trace,
}

impl From<LogMode> for log::LevelFilter {
    fn from(mode: LogMode) -> Self {
        match mode {
            LogMode::Off => log::LevelFilter::Off,
            LogMode::Error => log::LevelFilter::Error,
            LogMode::Warn => log::LevelFilter::Warn,
            LogMode::Info => log::LevelFilter::Info,
            LogMode::Debug => log::LevelFilter::Debug,
            LogMode::Trace => log::LevelFilter::Trace,
        }
    }
}

impl From<LogMode> for tracing_subscriber::filter::LevelFilter {
    fn from(mode: LogMode) -> Self {
        match mode {
            LogMode::Off => tracing_subscriber::filter::LevelFilter::OFF,
            LogMode::Error => tracing_subscriber::filter::LevelFilter::ERROR,
            LogMode::Warn => tracing_subscriber::filter::LevelFilter::WARN,
            LogMode::Info => tracing_subscriber::filter::LevelFilter::INFO,
            LogMode::Debug => tracing_subscriber::filter::LevelFilter::DEBUG,
            LogMode::Trace => tracing_subscriber::filter::LevelFilter::TRACE,
        }
    }
}

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

    /// Set the logging verbosity level.
    #[arg(
        short = 'l',
        long = "log-mode",
        alias = "log-level",
        value_enum,
        help = "Set the logging verbosity level"
    )]
    pub log_mode: Option<LogMode>,

    /// Write log output to a file instead of the console.
    #[arg(
        short = 'f',
        long = "log-file",
        alias = "log-output",
        value_name = "PATH",
        help = "Write log output to the specified file instead of the console"
    )]
    pub log_file: Option<PathBuf>,

    /// Export Chrome DevTools / Perfetto trace JSON file for visual profiling.
    #[arg(
        long = "profile-chrome",
        alias = "trace-chrome",
        value_name = "PATH",
        help = "Export Chrome DevTools / Perfetto trace JSON file to visualize thread flame charts and bottlenecks"
    )]
    pub profile_chrome: Option<PathBuf>,

    #[arg(
        long,
        help = "Disable direct syscall anomaly detection and stack tracing"
    )]
    pub disable_syscalls: bool,

    #[arg(
        long,
        help = "Disable system process tree and module mapping context tracking"
    )]
    pub disable_context: bool,

    #[arg(
        long,
        help = "Skip driver service loading and PPL elevation (standalone ETW mode)"
    )]
    pub skip_driver: bool,
}
