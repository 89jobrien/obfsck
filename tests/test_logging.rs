#![cfg(feature = "analyzer")]

use obfsck::logging::{LogFormat, LogFormat::*};

#[test]
fn parse_log_format_defaults_to_json() {
    assert_eq!(LogFormat::parse(None), Json);
    assert_eq!(LogFormat::parse(Some("")), Json);
    assert_eq!(LogFormat::parse(Some("json")), Json);
    assert_eq!(LogFormat::parse(Some("unknown")), Json);
}

#[test]
fn parse_log_format_recognizes_pretty_robustly() {
    assert_eq!(LogFormat::parse(Some("pretty")), Pretty);
    assert_eq!(LogFormat::parse(Some(" Pretty ")), Pretty);
    assert_eq!(LogFormat::parse(Some(" PRETTY ")), Pretty);
}
