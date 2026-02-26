use clap::Parser;
use obfsck::api::run_server;
use tracing::{error, info};
use tracing_subscriber::{EnvFilter, fmt};

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
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("obfsck=info,tower_http=debug,warn"));

    let format = std::env::var("LOG_FORMAT").unwrap_or_else(|_| "json".to_string());

    match format.as_str() {
        "pretty" => fmt().with_env_filter(env_filter).pretty().init(),
        _ => fmt().with_env_filter(env_filter).json().init(),
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
