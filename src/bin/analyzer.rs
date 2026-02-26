use clap::Parser;
use obfsck::analyzer::{run_from_args, CliArgs};
use tracing::error;

fn main() {
    obfsck::logging::init(obfsck::ANALYZER_DEFAULT_FILTER);
    let args = CliArgs::parse();
    match run_from_args(args) {
        Ok(code) => std::process::exit(code),
        Err(err) => {
            error!(error = %err, "Fatal error");
            std::process::exit(1);
        }
    }
}
