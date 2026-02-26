use clap::Parser;
use obfsck::analyzer::{run_from_args, CliArgs};
use tracing::error;

const DEFAULT_FILTER: &str = "obfsck=info,warn";

fn main() {
    obfsck::logging::init(DEFAULT_FILTER);
    let args = CliArgs::parse();
    match run_from_args(args) {
        Ok(code) => std::process::exit(code),
        Err(err) => {
            error!(error = %err, "Fatal error");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::DEFAULT_FILTER;

    #[test]
    fn default_filter_is_expected_value() {
        assert_eq!(DEFAULT_FILTER, "obfsck=info,warn");
    }
}
