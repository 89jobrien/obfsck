# /// script
# requires-python = ">=3.11"
# dependencies = [
#   "rich",
#   "pyyaml",
# ]
# ///

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import yaml
from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

BINARY = Path(__file__).parent.parent / "target" / "release" / "redact"
EXAMPLES_DIR = Path(__file__).parent / "examples"
console = Console()


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
    if not BINARY.exists():
        console.print(
            f"[bold red]Error:[/bold red] binary not found at [bold]{BINARY}[/bold]\n"
            "Run [bold]cargo build --release[/bold] first.",
            highlight=False,
        )
        sys.exit(1)


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
    return parser.parse_args()


def main() -> None:
    args = parse_args()
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
