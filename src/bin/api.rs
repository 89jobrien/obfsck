use clap::Parser;
use obfsck::api::run_server;
use tracing::{error, info};

const DEFAULT_FILTER: &str = "obfsck=info,tower_http=debug,warn";

#[derive(Debug, Parser)]
#[command(name = "analysis-api")]
#[command(about = "REST API for AI-powered alert analysis")]
struct Args {
    #[arg(long, default_value = "0.0.0.0")]
    host: String,
    #[arg(short = 'p', long, default_value_t = 5000)]
    port: u16,
}

#[tokio::main]
async fn main() {
    obfsck::logging::init(DEFAULT_FILTER);
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
    use super::DEFAULT_FILTER;

    #[test]
    fn default_filter_is_expected_value() {
        assert_eq!(DEFAULT_FILTER, "obfsck=info,tower_http=debug,warn");
    }
}
