use clap::Parser;
use obfsck::analyzer::{CliArgs, run_from_args};
use tracing::error;
use tracing_subscriber::{EnvFilter, fmt};

fn init_logging() {
    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("obfsck=info,warn"));

    let format = std::env::var("LOG_FORMAT").unwrap_or_else(|_| "json".to_string());

    match format.as_str() {
        "pretty" => fmt().with_env_filter(env_filter).pretty().init(),
        _ => fmt().with_env_filter(env_filter).json().init(),
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
