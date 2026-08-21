# /// script
# requires-python = ">=3.11"
# dependencies = [
#   "rich",
#   "pyyaml",
# ]
# ///

from __future__ import annotations

import argparse
import json
import re
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import yaml
from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

BIN_DIR = Path(__file__).parent.parent / "target" / "release"
BINARY = BIN_DIR / "redact"
EXAMPLES_DIR = Path(__file__).parent / "examples"
console = Console()


def bin_path(name: str) -> Path:
    return BIN_DIR / name


def check_bin(name: str) -> Path:
    path = bin_path(name)
    if not path.exists():
        console.print(
            f"[bold red]Error:[/bold red] binary not found at [bold]{path}[/bold]\n"
            "Run [bold]cargo build --release --features analyzer[/bold] first.",
            highlight=False,
        )
        sys.exit(1)
    return path


def run_bin(
    name: str, args: list[str], stdin: Optional[str] = None, timeout: float = 10.0
) -> subprocess.CompletedProcess:
    path = check_bin(name)
    return subprocess.run(
        [str(path), *args], input=stdin, capture_output=True, text=True, timeout=timeout
    )


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@dataclass
class Example:
    label: str
    type: str          # "kv" or "block"
    input: str
    level: Optional[str] = None  # per-example level override


@dataclass
class Fixture:
    title: str
    description: str
    level: str
    disabled: bool
    examples: list[Example]


def load_fixture(path: Path) -> Fixture:
    raw = yaml.safe_load(path.read_text())
    examples = [
        Example(
            label=ex["label"],
            type=ex["type"],
            input=ex["input"],
            level=ex.get("level"),
        )
        for ex in raw.get("examples", [])
    ]
    return Fixture(
        title=raw["title"],
        description=raw["description"],
        level=raw.get("level", "standard"),
        disabled=raw.get("disabled", False),
        examples=examples,
    )


def load_all_fixtures() -> list[Fixture]:
    paths = sorted(EXAMPLES_DIR.glob("*.yaml"))
    return [load_fixture(p) for p in paths]


def redact(text: str, level: str) -> str:
    result = subprocess.run(
        [str(BINARY), "--level", level],
        input=text,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        console.print(
            f"[bold red]Error:[/bold red] redact exited {result.returncode}\n{result.stderr}"
        )
        sys.exit(1)
    return result.stdout


_REDACTED_RE = re.compile(r"\[REDACTED[^\]]*\]")


def highlight_redacted(text: str) -> Text:
    result = Text()
    last = 0
    for m in _REDACTED_RE.finditer(text):
        if m.start() > last:
            result.append(text[last : m.start()])
        result.append(m.group(), style="bold red")
        last = m.end()
    if last < len(text):
        result.append(text[last:])
    return result


def render_kv_table(examples: list[Example], file_level: str) -> Table:
    table = Table(show_header=True, header_style="bold", expand=True, show_lines=False)
    table.add_column("Original", ratio=1, overflow="fold")
    table.add_column("Redacted", ratio=1, overflow="fold")
    for ex in examples:
        level = ex.level or file_level
        original = ex.input.strip()
        redacted_str = redact(original, level).strip()
        label_cell = Text(f"[{ex.label}]\n", style="dim") + Text(original)
        redacted_cell = Text(f"[{ex.label}]\n", style="dim") + highlight_redacted(redacted_str)
        table.add_row(label_cell, redacted_cell)
    return table


def render_block_pair(ex: Example, file_level: str) -> None:
    level = ex.level or file_level
    original = ex.input.rstrip("\n")
    redacted_str = redact(ex.input, level).rstrip("\n")
    console.print(Panel(original, title=f"[bold]{ex.label}[/bold] — Input", border_style="dim"))
    console.print(
        Panel(
            highlight_redacted(redacted_str),
            title=f"[bold]{ex.label}[/bold] — Redacted",
            border_style="red",
        )
    )


def render_fixture(fixture: Fixture) -> None:
    console.print(Rule(f"[bold]{fixture.title}[/bold]  [dim]{fixture.description}[/dim]"))

    if fixture.disabled:
        console.print(
            Panel(
                "[yellow]⚠  This group is disabled by default.[/yellow]\n"
                "Enable it in [bold]config/secrets.yaml[/bold] under the relevant group.\n"
                "Examples below show pass-through (no redaction) until enabled.",
                border_style="yellow",
            )
        )

    kv_examples = [e for e in fixture.examples if e.type == "kv"]
    block_examples = [e for e in fixture.examples if e.type == "block"]

    if kv_examples:
        console.print(render_kv_table(kv_examples, fixture.level))

    for ex in block_examples:
        render_block_pair(ex, fixture.level)

    console.print()


BANNER = """\
[bold]obfsck[/bold] — redact secrets & PII before LLM analysis
[dim]Levels:[/dim]  [bold]minimal[/bold] secrets only  ·  \
[bold]standard[/bold] + IPs, emails, containers, users  ·  \
[bold]paranoid[/bold] + paths, hostnames, high-entropy"""


def showcase_mode() -> None:
    console.print(Rule("[bold cyan]obfsck demo[/bold cyan]"))
    console.print(Panel(BANNER, border_style="cyan"))
    console.print()
    fixtures = load_all_fixtures()
    for fixture in fixtures:
        render_fixture(fixture)


def file_mode(path: Path, level: str) -> None:
    text = path.read_text()
    redacted_str = redact(text, level)
    console.print(Rule(f"[bold]{path.name}[/bold]  [dim](level: {level})[/dim]"))
    console.print(Panel(text.rstrip("\n"), title="Input", border_style="dim"))
    console.print(
        Panel(
            highlight_redacted(redacted_str.rstrip("\n")),
            title="Redacted",
            border_style="red",
        )
    )


def check_binary() -> None:
    check_bin("redact")


# ---------------------------------------------------------------------------
# scan — unified diff scanner combining the native obfsck patterns + gitleaks
# ---------------------------------------------------------------------------

SAMPLE_DIFF = """\
diff --git a/config.py b/config.py
index 1234567..89abcde 100644
--- a/config.py
+++ b/config.py
@@ -1,3 +1,4 @@
 import os
+AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
 DEBUG = False
 API_TIMEOUT = 30
"""


def demo_scan() -> None:
    console.print(Rule("[bold cyan]scan[/bold cyan]  [dim]— unified diff secret scanner[/dim]"))
    console.print(
        Panel(
            SAMPLE_DIFF.rstrip("\n"),
            title="Sample `git diff --staged` input",
            border_style="dim",
        )
    )
    result = run_bin("scan", ["--level", "minimal", "--no-gitleaks"], stdin=SAMPLE_DIFF)
    style = "red" if result.returncode == 1 else "green"
    console.print(
        Panel(
            (result.stderr or result.stdout).rstrip("\n"),
            title=f"scan output (exit {result.returncode})",
            border_style=style,
        )
    )
    console.print()


# ---------------------------------------------------------------------------
# obfsck-mcp — JSON-RPC stdio server (audit + generate-filters tools)
# ---------------------------------------------------------------------------


def mcp_request(method: str, params: Optional[dict] = None, req_id: int = 1) -> dict:
    req = {"jsonrpc": "2.0", "id": req_id, "method": method, "params": params or {}}
    result = run_bin("obfsck-mcp", [], stdin=json.dumps(req) + "\n")
    return json.loads(result.stdout.strip().splitlines()[-1])


def demo_mcp() -> None:
    console.print(Rule("[bold cyan]obfsck-mcp[/bold cyan]  [dim]— JSON-RPC stdio MCP server[/dim]"))

    tools_resp = mcp_request("tools/list")
    console.print(
        Panel(
            json.dumps(tools_resp, indent=2),
            title="tools/list",
            border_style="dim",
        )
    )

    audit_req = {
        "name": "audit",
        "arguments": {"text": SAMPLE_DIFF},
    }
    audit_resp = mcp_request("tools/call", audit_req, req_id=2)
    console.print(
        Panel(
            json.dumps(audit_resp, indent=2),
            title="tools/call → audit",
            border_style="red",
        )
    )
    console.print()


# ---------------------------------------------------------------------------
# analyzer — LLM-powered alert analysis CLI
# ---------------------------------------------------------------------------


def demo_analyzer() -> None:
    console.print(
        Rule("[bold cyan]analyzer[/bold cyan]  [dim]— LLM-powered alert analysis CLI[/dim]")
    )
    console.print(
        Panel(
            "No live Loki/VictoriaLogs backend is running in this demo environment, "
            "so this run shows the [bold]miette[/bold] fancy diagnostic that surfaces "
            "when the log backend is unreachable — the same path a real deployment "
            "hits on a misconfigured LOKI_URL.",
            border_style="dim",
        )
    )
    result = run_bin(
        "analyzer",
        ["--dry-run", "--last", "5m", "--limit", "1", "--loki-url", "http://127.0.0.1:1"],
        timeout=15,
    )
    console.print(
        Panel(
            result.stderr.rstrip("\n") or "(no output)",
            title=f"analyzer output (exit {result.returncode})",
            border_style="yellow",
        )
    )
    console.print()


# ---------------------------------------------------------------------------
# api — axum REST server
# ---------------------------------------------------------------------------


def http_get(url: str, timeout: float = 2.0) -> tuple[int, str]:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", errors="replace")


def demo_api() -> None:
    console.print(Rule("[bold cyan]api[/bold cyan]  [dim]— axum REST server[/dim]"))
    path = check_bin("api")
    port = free_port()
    proc = subprocess.Popen(
        [str(path), "--host", "127.0.0.1", "--port", str(port)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        base = f"http://127.0.0.1:{port}"
        deadline = time.monotonic() + 5.0
        status, body = 0, ""
        while time.monotonic() < deadline:
            try:
                status, body = http_get(f"{base}/health")
                break
            except (urllib.error.URLError, ConnectionError):
                time.sleep(0.1)
        console.print(
            Panel(body or "(server did not respond)", title=f"GET /health ({status})", border_style="green")
        )

        _, index_body = http_get(f"{base}/")
        snippet = index_body[:300] + ("…" if len(index_body) > 300 else "")
        console.print(Panel(snippet, title="GET / (first 300 chars)", border_style="dim"))
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
    console.print()


# ---------------------------------------------------------------------------
# tour — run every binary in sequence
# ---------------------------------------------------------------------------


def tour_mode() -> None:
    console.print(Rule("[bold cyan]obfsck — full binary tour[/bold cyan]"))
    console.print(
        Panel(BANNER, title="redact", border_style="cyan")
    )
    render_fixture(load_fixture(EXAMPLES_DIR / "00_levels.yaml"))
    demo_scan()
    demo_mcp()
    demo_analyzer()
    demo_api()
    console.print(Rule("[bold green]tour complete[/bold green]"))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="obfsck visual demo",
        epilog="--level only applies in file mode; showcase mode uses fixture-defined levels.",
    )
    parser.add_argument("file", nargs="?", help="File to redact (omit for full showcase)")
    parser.add_argument(
        "--level",
        choices=["minimal", "standard", "paranoid"],
        default="standard",
        help="Obfuscation level for file mode (default: standard)",
    )
    parser.add_argument(
        "--bin",
        choices=["redact", "scan", "mcp", "analyzer", "api", "all"],
        default="redact",
        help="Which binary to showcase (default: redact). 'all' tours every binary.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if args.bin == "all":
        tour_mode()
        return
    if args.bin == "scan":
        demo_scan()
        return
    if args.bin == "mcp":
        demo_mcp()
        return
    if args.bin == "analyzer":
        demo_analyzer()
        return
    if args.bin == "api":
        demo_api()
        return

    check_binary()
    if args.file:
        path = Path(args.file)
        if not path.exists():
            console.print(f"[bold red]Error:[/bold red] file not found: {args.file}")
            sys.exit(1)
        file_mode(path, args.level)
    else:
        showcase_mode()


if __name__ == "__main__":
    main()
