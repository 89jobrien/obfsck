use tracing_subscriber::{fmt, EnvFilter};

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
/// The log format can be controlled via the `LOG_FORMAT` environment variable:
/// - `pretty` - Human-readable pretty format
/// - `json` (default) - Structured JSON format
pub fn init(default_filter: &str) {
    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_filter));
    let format_env = std::env::var("LOG_FORMAT").ok();

    match LogFormat::parse(format_env.as_deref()) {
        LogFormat::Pretty => fmt().with_env_filter(env_filter).pretty().init(),
        LogFormat::Json => fmt().with_env_filter(env_filter).json().init(),
    }
}

#[cfg(test)]
mod tests {
    use super::{LogFormat, LogFormat::*};

    #[test]
    fn parse_log_format_defaults_to_json() {
        assert_eq!(LogFormat::parse(None), Json);
        assert_eq!(LogFormat::parse(Some("")), Json);
        assert_eq!(LogFormat::parse(Some("json")), Json);
        assert_eq!(LogFormat::parse(Some("unknown")), Json);
    }

    #[test]
    fn parse_log_format_recognizes_pretty_robustly() {
        assert_eq!(LogFormat::parse(Some("pretty")), Pretty);
        assert_eq!(LogFormat::parse(Some(" Pretty ")), Pretty);
        assert_eq!(LogFormat::parse(Some(" PRETTY ")), Pretty);
    }
}
