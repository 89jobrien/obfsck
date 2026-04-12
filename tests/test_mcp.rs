/// Tests for obfsck MCP server mode (obfsck-11).
///
/// Test order follows the TDD cycle:
///   1. Auditor port — AuditHit aggregation
///   2. FilterSuggester port — pattern suggestion from examples
///   3. MCP protocol — JSON-RPC framing and tool dispatch
use obfsck::mcp::{
    Auditor, FilterSuggester, ObfsckAuditor, PatternSuggester,
    protocol::{JsonRpcRequest, dispatch_tool},
};

// ---------------------------------------------------------------------------
// Auditor port
// ---------------------------------------------------------------------------

#[test]
fn auditor_returns_empty_hits_for_clean_input() {
    let auditor = ObfsckAuditor;
    let hits = auditor.audit("no secrets here");
    assert!(hits.is_empty());
}

#[test]
fn auditor_counts_hits_for_matching_pattern() {
    let auditor = ObfsckAuditor;
    // A GitHub PAT triggers the gh-pat pattern.
    let hits = auditor.audit("token ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    assert!(!hits.is_empty(), "expected at least one hit");
    let total: usize = hits.iter().map(|h| h.count).sum();
    assert_eq!(total, 1);
}

#[test]
fn auditor_aggregates_multiple_matches_of_same_pattern() {
    let auditor = ObfsckAuditor;
    let input = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa and \
                 ghp_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let hits = auditor.audit(input);
    let total: usize = hits.iter().map(|h| h.count).sum();
    assert_eq!(total, 2);
}

#[test]
fn auditor_hit_has_label_and_count() {
    let auditor = ObfsckAuditor;
    let hits = auditor.audit("ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    assert!(!hits.is_empty());
    assert!(!hits[0].label.is_empty());
    assert!(hits[0].count > 0);
}

// ---------------------------------------------------------------------------
// FilterSuggester port
// ---------------------------------------------------------------------------

#[test]
fn suggester_returns_empty_for_clean_examples() {
    let suggester = PatternSuggester;
    let suggestions = suggester.suggest(&["hello world".to_string(), "no secrets".to_string()]);
    assert!(suggestions.is_empty());
}

#[test]
fn suggester_proposes_pattern_for_known_secret_example() {
    let suggester = PatternSuggester;
    let examples = vec!["ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string()];
    let suggestions = suggester.suggest(&examples);
    assert!(!suggestions.is_empty(), "expected at least one suggestion");
    assert!(!suggestions[0].label.is_empty());
    assert!(!suggestions[0].pattern.is_empty());
}

#[test]
fn suggestion_pattern_is_valid_regex() {
    let suggester = PatternSuggester;
    let examples = vec!["ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string()];
    let suggestions = suggester.suggest(&examples);
    for s in &suggestions {
        assert!(
            regex::Regex::new(&s.pattern).is_ok(),
            "invalid regex: {}",
            s.pattern
        );
    }
}

// ---------------------------------------------------------------------------
// MCP JSON-RPC protocol
// ---------------------------------------------------------------------------

#[test]
fn jsonrpc_request_deserializes_initialize() {
    let raw = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#;
    let req: JsonRpcRequest = serde_json::from_str(raw).expect("deserialize");
    assert_eq!(req.method, "initialize");
}

#[test]
fn jsonrpc_request_deserializes_tools_list() {
    let raw = r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#;
    let req: JsonRpcRequest = serde_json::from_str(raw).expect("deserialize");
    assert_eq!(req.method, "tools/list");
}

#[test]
fn tools_list_response_includes_audit_and_generate_filters() {
    let req = JsonRpcRequest {
        jsonrpc: "2.0".into(),
        id: serde_json::Value::Number(1.into()),
        method: "tools/list".into(),
        params: serde_json::Value::Null,
    };
    let resp = dispatch_tool(&req);
    let tools = resp
        .result
        .as_ref()
        .and_then(|r| r.get("tools"))
        .and_then(|t| t.as_array())
        .expect("tools array");
    let names: Vec<&str> = tools
        .iter()
        .filter_map(|t| t.get("name").and_then(|n| n.as_str()))
        .collect();
    assert!(names.contains(&"audit"), "missing audit tool");
    assert!(
        names.contains(&"generate-filters"),
        "missing generate-filters tool"
    );
}

#[test]
fn dispatch_audit_tool_returns_hits_array() {
    let params = serde_json::json!({
        "name": "audit",
        "arguments": {
            "text": "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        }
    });
    let req = JsonRpcRequest {
        jsonrpc: "2.0".into(),
        id: serde_json::Value::Number(2.into()),
        method: "tools/call".into(),
        params,
    };
    let resp = dispatch_tool(&req);
    assert!(resp.error.is_none(), "unexpected error: {:?}", resp.error);
    let hits = resp
        .result
        .as_ref()
        .and_then(|r| r.get("hits"))
        .and_then(|h| h.as_array())
        .expect("hits array");
    assert!(!hits.is_empty());
}

#[test]
fn dispatch_generate_filters_returns_suggestions_array() {
    let params = serde_json::json!({
        "name": "generate-filters",
        "arguments": {
            "examples": ["ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]
        }
    });
    let req = JsonRpcRequest {
        jsonrpc: "2.0".into(),
        id: serde_json::Value::Number(3.into()),
        method: "tools/call".into(),
        params,
    };
    let resp = dispatch_tool(&req);
    assert!(resp.error.is_none(), "unexpected error: {:?}", resp.error);
    let suggestions = resp
        .result
        .as_ref()
        .and_then(|r| r.get("suggestions"))
        .and_then(|s| s.as_array())
        .expect("suggestions array");
    assert!(!suggestions.is_empty());
}

#[test]
fn dispatch_unknown_tool_returns_error() {
    let params = serde_json::json!({"name": "nonexistent", "arguments": {}});
    let req = JsonRpcRequest {
        jsonrpc: "2.0".into(),
        id: serde_json::Value::Number(9.into()),
        method: "tools/call".into(),
        params,
    };
    let resp = dispatch_tool(&req);
    assert!(resp.error.is_some(), "expected error for unknown tool");
}

#[test]
fn jsonrpc_response_includes_matching_id() {
    let req = JsonRpcRequest {
        jsonrpc: "2.0".into(),
        id: serde_json::Value::Number(42.into()),
        method: "tools/list".into(),
        params: serde_json::Value::Null,
    };
    let resp = dispatch_tool(&req);
    assert_eq!(resp.id, serde_json::Value::Number(42.into()));
}
