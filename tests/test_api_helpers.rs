use obfsck::api::{get_cache_key, normalize_output, parse_boolish};

#[test]
fn normalize_replaces_variable_fields() {
    let out =
        "2026-01-09T12:34:56Z pid=1234 user_uid=1000 container_id=abcdef1234567890 src=10.1.2.3";
    let normalized = normalize_output(out);
    assert!(normalized.contains("[TIME]"));
    assert!(normalized.contains("pid=[ID]"));
    assert!(normalized.contains("[CID]"));
    assert!(normalized.contains("[IP]"));
}

#[test]
fn cache_key_is_stable() {
    let a = get_cache_key("pid=1 src=1.2.3.4", "RuleA");
    let b = get_cache_key("pid=2 src=5.6.7.8", "RuleA");
    assert_eq!(a, b);
}

#[test]
fn parse_boolish_works() {
    assert!(parse_boolish(Some("true"), false));
    assert!(parse_boolish(Some("1"), false));
    assert!(!parse_boolish(Some("false"), true));
    assert!(parse_boolish(None, true));
}
