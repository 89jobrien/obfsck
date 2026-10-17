//! Deprecated `scan` binary that forwards to the canonical scanning command.
//!
//! Retained for compatibility with existing pre-commit hooks and CI jobs that
//! invoke `scan` directly. New callers should use `obfsck scan`.

use clap::Parser;
use obfsck::scan::{ScanArgs, run_scan_from_args};

fn main() {
    let args = ScanArgs::parse();
    eprintln!("warning: 'scan' is deprecated; use 'obfsck scan' instead");
    match run_scan_from_args(args) {
        Ok(code) => std::process::exit(code),
        Err(err) => {
            eprintln!("{err:?}");
            std::process::exit(2);
        }
    }
}
