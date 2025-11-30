//! Logging infrastructure for AD Tier Model
//!
//! This module sets up file-based logging to ADTier.log in the executable's directory.

use std::path::PathBuf;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

/// Get the directory containing the executable
fn get_executable_dir() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."))
}

/// Initialize logging to ADTier.log in the executable's directory.
///
/// Returns a guard that must be kept alive for the duration of the program
/// to ensure all logs are flushed to disk.
pub fn init_logging() -> WorkerGuard {
    let log_dir = get_executable_dir();

    // Create a file appender that writes to ADTier.log
    let file_appender = tracing_appender::rolling::never(&log_dir, "ADTier.log");
    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

    // Set up the subscriber with file output
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::registry()
        .with(env_filter)
        .with(
            fmt::layer()
                .with_writer(non_blocking)
                .with_ansi(false)
                .with_target(true)
                .with_thread_ids(true)
                .with_file(true)
                .with_line_number(true)
        )
        .init();

    guard
}
