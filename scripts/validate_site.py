#!/usr/bin/env python3
"""Validate site HTML: JSON parses, tags balance, no stale references."""
import json
import re
import sys
from html.parser import HTMLParser
from pathlib import Path

SITE = Path(__file__).resolve().parent.parent / "site"
VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link",
        "meta", "param", "source", "track", "wbr"}


class Balance(HTMLParser):
    def __init__(self):
        super().__init__()
        self.stack = []
        self.errors = []

    def handle_starttag(self, tag, attrs):
        if tag not in VOID:
            self.stack.append((tag, self.getpos()))

    def handle_endtag(self, tag):
        if tag in VOID:
            return
        if not self.stack:
            self.errors.append(f"stray </{tag}> at {self.getpos()}")
            return
        open_tag, pos = self.stack.pop()
        if open_tag != tag:
            self.errors.append(
                f"</{tag}> at {self.getpos()} closes <{open_tag}> opened at {pos}")


def main() -> int:
    failures = []

    for path in sorted(SITE.rglob("*.json")):
        try:
            json.loads(path.read_text(encoding="utf-8"))
            print(f"ok    {path.relative_to(SITE.parent)}")
        except Exception as exc:
            failures.append(f"BAD JSON {path}: {exc}")

    for path in sorted(SITE.glob("*.html")):
        parser = Balance()
        parser.feed(path.read_text(encoding="utf-8"))
        if parser.errors:
            failures.extend(f"BAD HTML {path.name}: {e}" for e in parser.errors)
        if parser.stack:
            failures.extend(
                f"BAD HTML {path.name}: unclosed <{t}> at {p}" for t, p in parser.stack
            )
        if not parser.errors and not parser.stack:
            print(f"ok    {path.relative_to(SITE.parent)}")

    # Every internal href/src must resolve.
    for path in sorted(SITE.glob("*.html")):
        text = path.read_text(encoding="utf-8")
        for attr in re.findall(r'(?:href|src)="([^"]+)"', text):
            if attr.startswith(("http", "#", "mailto:")):
                continue
            target = attr.split("#")[0].split("?")[0]
            if target and not (SITE / target).exists():
                failures.append(f"BAD LINK {path.name} -> {attr}")

    for line in failures:
        print(line)
    print(f"\n{len(failures)} problem(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())