use clap::Parser;
use miette::Result;
use obfsck::cli::{RedactArgs, run_redact_from_args};

fn main() -> Result<()> {
    let args = RedactArgs::parse();
    eprintln!("warning: 'redact' is deprecated; use 'obfsck redact' instead");
    run_redact_from_args(args)
}
