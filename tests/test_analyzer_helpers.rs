use obfsck::analyzer::{expand_env_string, parse_last};

#[test]
fn parses_last_durations() {
    assert!(parse_last("15m").is_ok());
    assert!(parse_last("1h").is_ok());
    assert!(parse_last("7d").is_ok());
    assert!(parse_last("10x").is_err());
    assert!(parse_last("0h").is_err());
    assert!(parse_last("-1h").is_err());
}

#[test]
fn expands_env_var_with_default() {
    let value = expand_env_string("${DOES_NOT_EXIST:-fallback}");
    assert_eq!(value, "fallback");
}

#[test]
fn expand_env_preserves_unicode() {
    let value = expand_env_string("préfix-${DOES_NOT_EXIST:-défaut}-suffixe");
    assert_eq!(value, "préfix-défaut-suffixe");
}
