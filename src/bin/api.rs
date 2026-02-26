use clap::Parser;
use obfsck::api::run_server;

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
    let args = Args::parse();
    eprintln!(
        "Alert Analysis API starting on http://{}:{}",
        args.host, args.port
    );

    if let Err(err) = run_server(args.host, args.port).await {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}
