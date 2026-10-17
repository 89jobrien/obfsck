#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# ///

"""Regenerate the CLI help section of site/cli.html from the real binaries.

The site previously carried transcribed `--help` output with a claim that it
"cannot drift". It did drift: three blocks showed the wrong command's output.
This script makes the transcription reproducible instead.

Usage:
    cargo install --path .
    uv run scripts/gen_cli_help.py          # rewrite site/cli.html in place
    uv run scripts/gen_cli_help.py --check  # exit 1 if stale, CI-friendly

`--check` is the form to wire into a gate: it fails when the committed page no
longer matches what the installed binaries actually print.
"""

from __future__ import annotations

import html
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PAGE = REPO_ROOT / "site" / "cli.html"

# (command argv, heading id, label, note shown above the block)
CANONICAL: list[tuple[list[str], str, str]] = [
    (["obfsck"], "obfsck---help", "obfsck --help"),
    (["obfsck", "redact"], "obfsck-redact---help", "obfsck redact --help"),
    (["obfsck", "analyze"], "obfsck-analyze---help", "obfsck analyze --help"),
    (["obfsck", "scan"], "obfsck-scan---help", "obfsck scan --help"),
]

# Deprecated aliases. Kept in the page because existing hooks still call them.
DEPRECATED: list[tuple[list[str], str, str, str]] = [
    (["redact"], "redact---help", "redact --help", "use `obfsck redact`"),
    (["analyzer"], "analyzer---help", "analyzer --help", "use `obfsck analyze`"),
    (["scan"], "scan---help", "scan --help", "use `obfsck scan`"),
]

# Binaries with no clap surface, so `--help` cannot document them.
NO_HELP: list[tuple[str, str, str]] = [
    ("obfsck-mcp", "obfsck-mcp", "MCP JSON-RPC server"),
    ("api", "api---help", "REST API server"),
]


def run_help(argv: list[str]) -> str:
    """Return the `--help` text for a command, or an explanatory note."""
    exe = shutil.which(argv[0])
    if exe is None:
        return f"$ {argv[0]} is not installed. Run: cargo install --path .\n"
    result = subprocess.run(
        [exe, *argv[1:], "--help"], capture_output=True, text=True, check=False
    )
    return (result.stdout or result.stderr).rstrip("\n")


def terminal(label: str, body: str) -> str:
    """Render one help capture as a terminal block with HTML escaping."""
    escaped = html.escape(body)
    return (
        f'<h3 id="{html.escape(label.replace(" ", "-"))}">{html.escape(label)}</h3>\n'
        f'<div class="terminal">\n'
        f'  <div class="terminal-bar"><span class="label">{html.escape(label)}</span></div>\n'
        f'  <pre><span class="prompt">$</span> {escaped}\n</pre>\n'
        f"</div>\n"
    )


def build_section() -> str:
    parts = [
        '      <section id="cli" class="reveal">\n',
        "        <h2>CLI</h2>\n",
        '        <p class="note">\n'
        "          Every block below is the real <code>--help</code> output, captured by\n"
        "          <code>scripts/gen_cli_help.py</code>. It is a transcription, so it can\n"
        "          drift; re-run that script after upgrading or changing any flag. Use\n"
        "          <code>--check</code> in CI to catch a stale page.\n"
        "        </p>\n",
        '        <h3 id="canonical-commands">Canonical commands</h3>\n',
        "        <p>\n"
        "          <code>obfsck</code> is the supported entry point. The standalone\n"
        "          <code>redact</code>, <code>analyzer</code>, and <code>scan</code>\n"
        "          binaries still exist for compatibility but warn on every run.\n"
        "        </p>\n",
    ]
    for argv, anchor, label in CANONICAL:
        parts.append(terminal(label, run_help(argv)))

    parts.append('        <h3 id="deprecated-binaries">Deprecated binaries</h3>\n')
    parts.append(
        "        <p>\n"
        "          Each of these prints a deprecation warning to stderr and forwards to\n"
        "          the canonical subcommand. They are kept so existing pre-commit hooks\n"
        "          and CI jobs keep working.\n"
        "        </p>\n"
    )
    for argv, anchor, label, replacement in DEPRECATED:
        body = run_help(argv)
        parts.append(
            f'        <p class="note">Deprecated &mdash; {html.escape(replacement)}.</p>\n'
        )
        parts.append(terminal(label, body))

    parts.append('        <h3 id="other-binaries">Other binaries</h3>\n')
    for label, anchor, description in NO_HELP:
        if label == "obfsck-mcp":
            parts.append(
                '        <p class="note">\n'
                "          <code>obfsck-mcp</code> reads JSON-RPC from stdin and does not use\n"
                "          clap, so it has no <code>--help</code>. It supports\n"
                "          <code>--version</code>. See the guide for the tool surface.\n"
                "        </p>\n"
            )
        else:
            parts.append(terminal(f"{label} --help", run_help([label])))

    parts.append("      </section>\n")
    return "".join(parts)


def main() -> int:
    section = build_section()
    current = PAGE.read_text(encoding="utf-8")
    start = current.index('      <section id="cli"')
    end = current.index("      </section>\n") + len("      </section>\n")
    updated = current[:start] + section + current[end:]

    if "--check" in sys.argv:
        if updated != current:
            print("site/cli.html is stale; run uv run scripts/gen_cli_help.py")
            return 1
        print("site/cli.html matches the installed binaries")
        return 0

    if updated == current:
        print("site/cli.html already up to date")
        return 0
    PAGE.write_text(updated, encoding="utf-8")
    print(f"rewrote {PAGE.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())