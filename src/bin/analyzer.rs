use clap::Parser;
use obfsck::analyzer::{run_from_args, CliArgs};
use tracing::error;
use tracing_subscriber::{fmt, EnvFilter};

const DEFAULT_FILTER: &str = "obfsck=info,warn";

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

fn init_logging() {
    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(DEFAULT_FILTER));
    let format_env = std::env::var("LOG_FORMAT").ok();

    match parse_log_format(format_env.as_deref()) {
        LogFormat::Pretty => fmt().with_env_filter(env_filter).pretty().init(),
        LogFormat::Json => fmt().with_env_filter(env_filter).json().init(),
    }
}

fn main() {
    init_logging();
    let args = CliArgs::parse();
    match run_from_args(args) {
        Ok(code) => std::process::exit(code),
        Err(err) => {
            error!(error = %err, "Fatal error");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_log_format, LogFormat, DEFAULT_FILTER};

    #[test]
    fn default_filter_is_expected_value() {
        assert_eq!(DEFAULT_FILTER, "obfsck=info,warn");
    }

    #[test]
    fn parse_log_format_defaults_to_json() {
        assert_eq!(parse_log_format(None), LogFormat::Json);
        assert_eq!(parse_log_format(Some("json")), LogFormat::Json);
        assert_eq!(parse_log_format(Some("nope")), LogFormat::Json);
    }

    #[test]
    fn parse_log_format_recognizes_pretty_robustly() {
        assert_eq!(parse_log_format(Some("pretty")), LogFormat::Pretty);
        assert_eq!(parse_log_format(Some(" Pretty ")), LogFormat::Pretty);
    }
}
