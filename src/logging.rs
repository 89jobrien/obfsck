use std::path::PathBuf;
use tracing_subscriber::{EnvFilter, Layer, fmt, layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    Json,
    Pretty,
}

impl LogFormat {
    pub fn parse(value: Option<&str>) -> Self {
        match value.map(str::trim).map(str::to_ascii_lowercase).as_deref() {
            Some("pretty") => Self::Pretty,
            _ => Self::Json,
        }
    }
}

/// Initialize tracing subscriber with the given default filter.
///
/// The default filter is used if the `RUST_LOG` environment variable is not set.
///
/// ## Environment Variables
///
/// - `RUST_LOG` - Log level filter (e.g., `obfsck=debug,tower_http=info`)
/// - `LOG_FORMAT` - Output format: `pretty` or `json` (default: `json`)
/// - `LOG_DIR` - Directory for log files (e.g., `~/logs/obfsck`)
///   - If set, logs are written to both stdout and timestamped files
///   - Files are named: `obfsck-YYYY-MM-DD-HH-MM-SS.log`
///   - If not set, logs only go to stdout
///
/// ## Examples
///
/// ```bash
/// # Pretty format to stdout only
/// LOG_FORMAT=pretty cargo run --bin analyzer
///
/// # JSON format to both stdout and files
/// LOG_DIR=~/logs/obfsck cargo run --bin api
///
/// # Pretty format to both stdout and files
/// LOG_FORMAT=pretty LOG_DIR=~/logs/obfsck cargo run --bin analyzer
/// ```
pub fn init(default_filter: &str) {
    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_filter));
    let format_env = std::env::var("LOG_FORMAT").ok();
    let log_format = LogFormat::parse(format_env.as_deref());

    // Check if file logging is enabled via LOG_DIR
    let log_dir = std::env::var("LOG_DIR").ok().and_then(|dir| {
        let expanded = shellexpand::tilde(&dir);
        let path = PathBuf::from(expanded.as_ref());

        // Create directory if it doesn't exist
        if let Err(e) = std::fs::create_dir_all(&path) {
            eprintln!("Failed to create log directory {}: {}", path.display(), e);
            return None;
        }

        Some(path)
    });

    match log_dir {
        Some(dir) => {
            // File logging enabled - use layered approach for both stdout and files
            let file_appender = tracing_appender::rolling::never(
                dir,
                format!(
                    "obfsck-{}.log",
                    chrono::Local::now().format("%Y-%m-%d-%H-%M-%S")
                ),
            );
            let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

            // Create stdout layer
            let stdout_layer = match log_format {
                LogFormat::Pretty => fmt::layer().pretty().boxed(),
                LogFormat::Json => fmt::layer().json().boxed(),
            };

            // Create file layer (always JSON for structured logs)
            let file_layer = fmt::layer().json().with_writer(non_blocking).boxed();

            // Combine layers
            tracing_subscriber::registry()
                .with(env_filter)
                .with(stdout_layer)
                .with(file_layer)
                .init();

            // Leak the guard so it lives for the program lifetime
            std::mem::forget(_guard);
        }
        None => {
            // No file logging - simple stdout only (original behavior)
            match log_format {
                LogFormat::Pretty => fmt().with_env_filter(env_filter).pretty().init(),
                LogFormat::Json => fmt().with_env_filter(env_filter).json().init(),
            }
        }
    }
}
