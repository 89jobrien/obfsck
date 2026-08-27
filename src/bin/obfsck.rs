use clap::Parser;
use obfsck::cli::{ObfsckArgs, run_from_args};

fn main() {
    let args = ObfsckArgs::parse();
    match run_from_args(args) {
        Ok(code) => std::process::exit(code),
        Err(err) => {
            eprintln!("{err:?}");
            std::process::exit(1);
        }
    }
}
