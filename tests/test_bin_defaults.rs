#![cfg(feature = "analyzer")]

#[test]
fn api_default_filter_is_expected_value() {
    assert_eq!(
        obfsck::API_DEFAULT_FILTER,
        "obfsck=info,tower_http=debug,warn"
    );
}

#[test]
fn analyzer_default_filter_is_expected_value() {
    assert_eq!(obfsck::ANALYZER_DEFAULT_FILTER, "obfsck=info,warn");
}
