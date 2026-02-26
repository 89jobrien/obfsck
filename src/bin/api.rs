use clap::Parser;
use obfsck::api::run_server;
use tracing::{error, info};
use tracing_subscriber::{EnvFilter, fmt};

const DEFAULT_FILTER: &str = "obfsck=info,tower_http=debug,warn";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LogFormat {
    Json,
    Pretty,
}

fn parse_log_format(value: Option<&str>) -> LogFormat {
    match value.map(str::trim).map(str::to_ascii_lowercase).as_deref() {
        Some("pretty") => LogFormat::Pretty,
        _ => LogFormat::Json,
    }
}

#[derive(Debug, Parser)]
#[command(name = "analysis-api")]
#[command(about = "REST API for AI-powered alert analysis")]
struct Args {
    #[arg(long, default_value = "0.0.0.0")]
    host: String,
    #[arg(short = 'p', long, default_value_t = 5000)]
    port: u16,
}

fn init_logging() {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(DEFAULT_FILTER));
    let format_env = std::env::var("LOG_FORMAT").ok();

    match parse_log_format(format_env.as_deref()) {
        LogFormat::Pretty => fmt().with_env_filter(env_filter).pretty().init(),
        LogFormat::Json => fmt().with_env_filter(env_filter).json().init(),
    }
}

#[tokio::main]
async fn main() {
    init_logging();
    let args = Args::parse();

    info!(
        host = %args.host,
        port = args.port,
        "Alert Analysis API starting"
    );

    if let Err(err) = run_server(args.host, args.port).await {
        error!(error = %err, "Server error");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::{DEFAULT_FILTER, LogFormat, parse_log_format};

    #[test]
    fn default_filter_is_expected_value() {
        assert_eq!(DEFAULT_FILTER, "obfsck=info,tower_http=debug,warn");
    }

    #[test]
    fn parse_log_format_defaults_to_json() {
        assert_eq!(parse_log_format(None), LogFormat::Json);
        assert_eq!(parse_log_format(Some("")), LogFormat::Json);
        assert_eq!(parse_log_format(Some("json")), LogFormat::Json);
        assert_eq!(parse_log_format(Some("unknown")), LogFormat::Json);
    }

    #[test]
    fn parse_log_format_recognizes_pretty_robustly() {
        assert_eq!(parse_log_format(Some("pretty")), LogFormat::Pretty);
        assert_eq!(parse_log_format(Some(" PRETTY ")), LogFormat::Pretty);
    }
}
