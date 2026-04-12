/// obfsck MCP server — exposes `audit` and `generate-filters` tools via JSON-RPC stdio.
///
/// mcpipe launches this binary and routes tool calls through the normal MCP protocol.
/// Usage (via mcpipe): auto-discovered via `--scan` once this binary is on PATH.
/// Direct usage: `echo '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' | mcp`
use obfsck::mcp::protocol::{JsonRpcRequest, dispatch_tool};
use std::io::{self, BufRead, Write};

fn main() {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) if l.trim().is_empty() => continue,
            Ok(l) => l,
            Err(e) => {
                eprintln!("obfsck-mcp: read error: {e}");
                break;
            }
        };

        let req: JsonRpcRequest = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                let err = serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": null,
                    "error": { "code": -32700, "message": format!("parse error: {e}") }
                });
                let _ = writeln!(out, "{}", serde_json::to_string(&err).unwrap_or_default());
                let _ = out.flush();
                continue;
            }
        };

        let resp = dispatch_tool(&req);
        match serde_json::to_string(&resp) {
            Ok(json) => {
                let _ = writeln!(out, "{json}");
                let _ = out.flush();
            }
            Err(e) => eprintln!("obfsck-mcp: serialize error: {e}"),
        }
    }
}
