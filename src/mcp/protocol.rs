use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{Auditor, FilterSuggester, ObfsckAuditor, PatternSuggester};

#[derive(Debug, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub id: Value,
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

#[derive(Debug, Serialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    pub id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

#[derive(Debug, Serialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
}

impl JsonRpcResponse {
    fn ok(id: Value, result: Value) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            id,
            result: Some(result),
            error: None,
        }
    }

    fn err(id: Value, code: i32, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            id,
            result: None,
            error: Some(JsonRpcError {
                code,
                message: message.into(),
            }),
        }
    }
}

const TOOL_AUDIT: &str = "audit";
const TOOL_GENERATE_FILTERS: &str = "generate-filters";

fn tools_schema() -> Value {
    serde_json::json!({
        "tools": [
            {
                "name": TOOL_AUDIT,
                "description": "Pipe text through obfsck and return pattern hit counts.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "text": { "type": "string", "description": "Text to audit." }
                    },
                    "required": ["text"]
                }
            },
            {
                "name": TOOL_GENERATE_FILTERS,
                "description": "Given example strings, suggest obfsck filter patterns.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "examples": {
                            "type": "array",
                            "items": { "type": "string" },
                            "description": "Example strings that should be redacted."
                        }
                    },
                    "required": ["examples"]
                }
            }
        ]
    })
}

pub fn dispatch_tool(req: &JsonRpcRequest) -> JsonRpcResponse {
    match req.method.as_str() {
        "initialize" => JsonRpcResponse::ok(
            req.id.clone(),
            serde_json::json!({
                "protocolVersion": "2024-11-05",
                "capabilities": { "tools": {} },
                "serverInfo": { "name": "obfsck", "version": env!("CARGO_PKG_VERSION") }
            }),
        ),
        "tools/list" => JsonRpcResponse::ok(req.id.clone(), tools_schema()),
        "tools/call" => dispatch_call(req),
        _ => JsonRpcResponse::err(req.id.clone(), -32601, "method not found"),
    }
}

fn dispatch_call(req: &JsonRpcRequest) -> JsonRpcResponse {
    let name = match req.params.get("name").and_then(|v| v.as_str()) {
        Some(n) => n,
        None => return JsonRpcResponse::err(req.id.clone(), -32602, "missing tool name"),
    };
    let args = req.params.get("arguments").unwrap_or(&Value::Null);

    match name {
        TOOL_AUDIT => {
            let text = match args.get("text").and_then(|v| v.as_str()) {
                Some(t) => t,
                None => {
                    return JsonRpcResponse::err(req.id.clone(), -32602, "missing argument: text");
                }
            };
            let auditor = ObfsckAuditor;
            let hits: Vec<Value> = auditor
                .audit(text)
                .into_iter()
                .map(|h| serde_json::json!({ "label": h.label, "count": h.count }))
                .collect();
            JsonRpcResponse::ok(req.id.clone(), serde_json::json!({ "hits": hits }))
        }
        TOOL_GENERATE_FILTERS => {
            let examples: Vec<String> = match args.get("examples").and_then(|v| v.as_array()) {
                Some(arr) => arr
                    .iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect(),
                None => {
                    return JsonRpcResponse::err(
                        req.id.clone(),
                        -32602,
                        "missing argument: examples",
                    );
                }
            };
            let suggester = PatternSuggester;
            let suggestions: Vec<Value> = suggester
                .suggest(&examples)
                .into_iter()
                .map(|s| serde_json::json!({ "pattern": s.pattern, "label": s.label }))
                .collect();
            JsonRpcResponse::ok(
                req.id.clone(),
                serde_json::json!({ "suggestions": suggestions }),
            )
        }
        _ => JsonRpcResponse::err(req.id.clone(), -32602, format!("unknown tool: {name}")),
    }
}
