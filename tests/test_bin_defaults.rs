#![cfg(feature = "analyzer")]

#[test]
fn api_default_filter_matches_expected() {
    let filter = obfsck::API_DEFAULT_FILTER;
    assert_eq!(filter, "obfsck=info,tower_http=debug,warn");
}

#[test]
fn analyzer_default_filter_matches_expected() {
    let filter = obfsck::ANALYZER_DEFAULT_FILTER;
    assert_eq!(filter, "obfsck=info,warn");
}
