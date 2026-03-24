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
    # wired in Task 5


if __name__ == "__main__":
    main()
