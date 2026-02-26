use clap::Parser;
use obfsck::analyzer::{CliArgs, run_from_args};

fn main() {
    let args = CliArgs::parse();
    match run_from_args(args) {
        Ok(code) => std::process::exit(code),
        Err(err) => {
            eprintln!("error: {err}");
            std::process::exit(1);
        }
    }
}
