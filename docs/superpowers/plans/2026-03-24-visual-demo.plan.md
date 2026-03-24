# Visual Demo Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a data-driven Python demo script (`demo/demo.py`) that showcases every obfsck redaction feature with rich terminal formatting, driven by YAML fixture files, and supports piping local files through the real `redact` binary.

**Architecture:** Single PEP 723 script loaded with `uv run`. Fixture files in `demo/examples/` define labeled examples (kv or block type). The script shells out to `target/release/redact` for all redaction — no logic reimplemented. Showcase mode iterates all fixtures using fixture-defined levels; file mode uses the CLI `--level` flag.

**Tech Stack:** Python 3.11+, `rich`, `pyyaml`, `uv` (runner), `target/release/redact` (Rust binary, must be pre-built)

---

## File Map

| File | Role |
|------|------|
| `demo/demo.py` | PEP 723 script — all Python logic |
| `demo/examples/00_levels.yaml` | Same input at minimal/standard/paranoid |
| `demo/examples/01_ai_apis.yaml` | Anthropic, OpenAI, Groq, HuggingFace, Replicate, Google |
| `demo/examples/02_cloud.yaml` | AWS, GCP, Azure, DigitalOcean, Cloudflare |
| `demo/examples/03_version_control.yaml` | GitHub, GitLab tokens |
| `demo/examples/04_communication.yaml` | Slack, Discord, Telegram |
| `demo/examples/05_payments.yaml` | Stripe, Twilio, SendGrid, Mailchimp, Mailgun |
| `demo/examples/06_databases.yaml` | Postgres, MySQL, MongoDB, Redis URIs |
| `demo/examples/07_package_managers.yaml` | npm, PyPI, NuGet tokens |
| `demo/examples/08_monitoring.yaml` | Sentry DSN |
| `demo/examples/09_generic.yaml` | JWT, private keys, bearer/basic auth, password fields |
| `demo/examples/10_paranoid_patterns.yaml` | All `paranoid_only: true` patterns from enabled groups |
| `demo/examples/11_pii.yaml` | SSN, credit card, phone, IBAN, passport, DL (group disabled by default) |
| `demo/examples/12_structural.yaml` | IPs, emails, containers, users, hostnames, paths |
| `demo/examples/13_log_block.yaml` | Realistic mixed log block |

---

## Pattern length reference

Several fixture inputs require exact character counts to match their regex. These are verified against `config/secrets.yaml`:

| Pattern | Key format | Notes |
|---|---|---|
| `anthropic_api_key` | `sk-ant-api03-` + 32+ chars | ≥32 alphanum after prefix |
| `google_api_key` | `AIza` + exactly 35 chars | `[0-9A-Za-z_-]{35}` |
| `aws_access_key` | `AKIA` + exactly 16 uppercase alphanum | |
| `digitalocean_pat` | `dop_v1_` + exactly 64 lowercase hex | `[a-f0-9]{64}` |
| `github_fine_grained` | `github_pat_` + 22 alphanum + `_` + 59 alphanum | exact lengths |
| `github_pat` | `ghp_` + 36+ alphanum | ≥36 |
| `slack_bot_token` | `xoxb-` + 10-13 digits + `-` + 10-13 digits + `-` + exactly 24 alphanum | |
| `discord_bot_token` | `MTI` (or similar prefix) + 23+ alphanum + `.` + 6 + `.` + exactly 27 | |
| `stripe_secret_key` | `sk_live_` or `sk_test_` + 24+ alphanum | **Do not use `STRIPE_SECRET_KEY=` as env var name** — triggers `password_field` pattern |
| `sendgrid_api_key` | `SG.` + exactly 22 + `.` + exactly 43 | |
| `npm_token` | `npm_` + exactly 36 alphanum | |
| `replicate_api_key` | `r8_` + exactly 40 alphanum | |
| `telegram_bot_token` | 8-10 digits + `:` + exactly 35 alphanum | paranoid_only |
| `aws_secret_key` | exactly 40 alphanum (avoid `+/` for clean word boundaries) | paranoid_only |
| `datadog_api_key` | exactly 32 lowercase hex | paranoid_only |
| `datadog_app_key` | exactly 40 lowercase hex | paranoid_only |
| `azure_client_secret` | exactly 34 alphanum | paranoid_only |
| `twilio_auth_token` | exactly 32 lowercase hex | paranoid_only |
| `cloudflare_api_key` | exactly 37 alphanum | paranoid_only |
| `pagerduty_api_key` | exactly 20 alphanum (avoid `+/`) | paranoid_only |
| `passport` | 1-2 uppercase letters + 6-9 digits | paranoid_only |
| `drivers_license_us` | 1 uppercase letter + exactly 7 digits | paranoid_only |

---

## Task 1: Scaffold — demo.py skeleton, CLI, binary check

**Files:**
- Create: `demo/demo.py`

- [ ] **Step 1: Create `demo/` directory and `demo.py` with PEP 723 header, imports, constants**

```python
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
```

- [ ] **Step 2: Add data types**

```python
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
```

- [ ] **Step 3: Add CLI + binary guard + stub main**

`--level` applies in file mode. In showcase mode, each fixture defines its own level; the CLI level is unused (this is noted in the help text).

```python
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
```

- [ ] **Step 4: Verify the script runs**

```bash
uv run demo/demo.py --help
```

Expected: usage line listing `file` positional and `--level` option with epilog note.

- [ ] **Step 5: Commit**

```bash
git add demo/demo.py
git commit -m "feat(demo): scaffold demo.py with CLI, binary check, data types"
```

---

## Task 2: Fixture loader

**Files:**
- Modify: `demo/demo.py`

- [ ] **Step 1: Add `load_fixture()` and `load_all_fixtures()`**

```python
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
```

- [ ] **Step 2: Smoke-test the loader**

Create a temporary fixture and verify parsing:

```bash
python3 -c "
import yaml; from pathlib import Path
raw = yaml.safe_load('''
title: Test
description: loader smoke test
level: minimal
examples:
  - label: one
    type: kv
    input: key=value
''')
print(raw['title'], len(raw['examples']))
"
```

Expected: `Test 1`

- [ ] **Step 3: Commit**

```bash
git add demo/demo.py
git commit -m "feat(demo): add fixture loader"
```

---

## Task 3: Core helpers — `redact()` and `highlight_redacted()`

**Files:**
- Modify: `demo/demo.py`

- [ ] **Step 1: Add `redact()`**

```python
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
```

- [ ] **Step 2: Add `highlight_redacted()`**

Scans text for `[REDACTED-*]` tokens and renders them bold red; everything else is plain.

```python
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
```

- [ ] **Step 3: Smoke-test both helpers (requires `cargo build --release` first)**

```bash
echo "ANTHROPIC_API_KEY=sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWXYZabcde" | \
  target/release/redact --level minimal
```

Expected: `ANTHROPIC_API_KEY=[REDACTED-ANTHROPIC-KEY]`

- [ ] **Step 4: Commit**

```bash
git add demo/demo.py
git commit -m "feat(demo): add redact() and highlight_redacted() helpers"
```

---

## Task 4: Renderers — kv table, block panels, fixture section

**Files:**
- Modify: `demo/demo.py`

- [ ] **Step 1: Add `render_kv_table()`**

Two equal flexible columns; each cell truncated by rich's `overflow="fold"`.

```python
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
```

- [ ] **Step 2: Add `render_block_pair()`**

```python
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
```

- [ ] **Step 3: Add `render_fixture()`**

Note: the disabled-group notice is rendered *before* the examples (not after as written in the spec). This is intentionally better UX — the reader sees the caveat before examining identical before/after output.

```python
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
```

- [ ] **Step 4: Commit**

```bash
git add demo/demo.py
git commit -m "feat(demo): add kv/block renderers and render_fixture()"
```

---

## Task 5: Showcase mode and file mode

**Files:**
- Modify: `demo/demo.py`

- [ ] **Step 1: Add `showcase_mode()`**

```python
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
```

- [ ] **Step 2: Add `file_mode()`**

```python
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
```

- [ ] **Step 3: Wire `main()`**

```python
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
```

- [ ] **Step 4: Commit**

```bash
git add demo/demo.py
git commit -m "feat(demo): add showcase_mode() and file_mode(), wire main()"
```

---

## Task 6: Fixture files 00–06

**Files:**
- Create: `demo/examples/00_levels.yaml` through `demo/examples/06_databases.yaml`

- [ ] **Step 1: Create `00_levels.yaml`**

Three consecutive kv rows using the same input, one per level. The input contains a secret (redacted at all levels), an IP + user (redacted at standard+), and a path (paranoid only).

```yaml
title: "Obfuscation Levels"
description: "Same input at each level — shows what each level adds"
level: minimal
examples:
  - label: "minimal  (secrets only)"
    type: kv
    level: minimal
    input: "user=alice ip=192.168.1.100 config=/home/alice/.config/app.json token=sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWXYZabcde"

  - label: "standard (+IPs, emails, containers, users)"
    type: kv
    level: standard
    input: "user=alice ip=192.168.1.100 config=/home/alice/.config/app.json token=sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWXYZabcde"

  - label: "paranoid (+paths, hostnames, high-entropy, paranoid_only patterns)"
    type: kv
    level: paranoid
    input: "user=alice ip=192.168.1.100 config=/home/alice/.config/app.json token=sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWXYZabcde"
```

- [ ] **Step 2: Create `01_ai_apis.yaml`**

Lengths verified against `config/secrets.yaml` patterns. Google: `AIza` + 35 chars. Replicate: `r8_` + 40 chars.

```yaml
title: "AI APIs"
description: "API keys for AI services — matched at all levels"
level: minimal
examples:
  - label: "Anthropic API key"
    type: kv
    input: "ANTHROPIC_API_KEY=sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWXYZabcde"

  - label: "OpenAI API key"
    type: kv
    input: "OPENAI_API_KEY=sk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn"

  - label: "Groq API key"
    type: kv
    input: "GROQ_API_KEY=gsk_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn"

  - label: "HuggingFace token"
    type: kv
    input: "HF_TOKEN=hf_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"

  - label: "Replicate API key"
    type: kv
    input: "REPLICATE_API_KEY=r8_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn"

  - label: "Google API key"
    type: kv
    input: "GOOGLE_API_KEY=AIzaABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi"
```

- [ ] **Step 3: Create `02_cloud.yaml`**

DigitalOcean PAT requires exactly 64 lowercase hex chars. Azure SAS: avoid hyphens in the date segment to prevent a trailing unmatched fragment.

```yaml
title: "Cloud Providers"
description: "AWS, GCP, Azure, DigitalOcean credentials"
level: minimal
examples:
  - label: "AWS access key"
    type: kv
    input: "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"

  - label: "GCP service account"
    type: kv
    input: "service_account=deploy-bot@my-project-123.iam.gserviceaccount.com"

  - label: "DigitalOcean personal access token"
    type: kv
    input: "DO_TOKEN=dop_v1_abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"

  - label: "Azure SAS token"
    type: kv
    input: "AZ_SAS=sig=ABCDEFGabcdefg123456&se=9999999999&sv=20210101&sp=r&sr=b"
```

- [ ] **Step 4: Create `03_version_control.yaml`**

GitHub fine-grained PAT: exactly 22 alphanum + `_` + exactly 59 alphanum.

```yaml
title: "Version Control"
description: "GitHub and GitLab access tokens"
level: minimal
examples:
  - label: "GitHub PAT (classic)"
    type: kv
    input: "GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmno"

  - label: "GitHub fine-grained PAT"
    type: kv
    input: "GITHUB_TOKEN=github_pat_ABCDEFGHIJKLMNOPQRSTUV_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567"

  - label: "GitLab PAT"
    type: kv
    input: "GITLAB_TOKEN=glpat-ABCDEFGHIJKLMNOPQRSTUVWXYZabcd"

  - label: "GitLab pipeline token"
    type: kv
    input: "CI_JOB_TOKEN=glptt-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn"
```

- [ ] **Step 5: Create `04_communication.yaml`**

Slack third segment: exactly 24 chars. Discord last segment: exactly 27 chars (use `MTI` prefix + 23+ chars in first segment).

```yaml
title: "Communication"
description: "Slack, Discord webhook and bot tokens"
level: minimal
examples:
  - label: "Slack bot token"
    type: kv
    input: "SLACK_BOT_TOKEN=xoxb-1234567890-1234567890123-ABCDEFGHIJKLMNOPQRSTUVWx"

  - label: "Slack webhook"
    type: kv
    input: "SLACK_WEBHOOK=https://hooks.slack.com/services/TABCDEFGH/BABCDEFGH/ABCDEFGHIJKLMNOPQRSTUVWxy"

  - label: "Discord bot token"
    type: kv
    input: "DISCORD_TOKEN=MTIABCDEFGHIJKLMNOPQRSTUVw.ABCDEf.ABCDEFGHIJKLMNOPQRSTUVWXYZa"

  - label: "Discord webhook"
    type: kv
    input: "DISCORD_WEBHOOK=https://discord.com/api/webhooks/123456789012345678/ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef"
```

- [ ] **Step 6: Create `05_payments.yaml`**

**Important:** Do not use `STRIPE_SECRET_KEY=` as the env var name — the `secret_key` substring triggers the `password_field` pattern before stripe. Use `STRIPE_API_KEY=` or `STRIPE_KEY=` instead. SendGrid: exactly 22 chars + exactly 43 chars in the two segments.

```yaml
title: "Payments & Messaging"
description: "Stripe, Twilio, SendGrid, Mailchimp, Mailgun API keys"
level: minimal
examples:
  - label: "Stripe secret key (live)"
    type: kv
    input: "STRIPE_API_KEY=sk_live_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef"

  - label: "Stripe secret key (test)"
    type: kv
    input: "STRIPE_API_KEY=sk_test_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef"

  - label: "SendGrid API key"
    type: kv
    input: "SENDGRID_API_KEY=SG.ABCDEFGHIJKLMNOPQRSTUV.ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq"

  - label: "Mailchimp API key"
    type: kv
    input: "MAILCHIMP_KEY=abcdef1234567890abcdef1234567890-us12"

  - label: "Mailgun API key"
    type: kv
    input: "MAILGUN_API_KEY=key-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef"
```

- [ ] **Step 7: Create `06_databases.yaml`**

```yaml
title: "Database URIs"
description: "Connection strings containing embedded credentials"
level: minimal
examples:
  - label: "PostgreSQL URI"
    type: kv
    input: "DATABASE_URL=postgres://alice:s3cr3tpassword@db.internal.example.com/myapp"

  - label: "MySQL URI"
    type: kv
    input: "DATABASE_URL=mysql://root:supersecret123@10.0.0.5/production"

  - label: "MongoDB URI"
    type: kv
    input: "MONGO_URI=mongodb+srv://appuser:M0ng0P4ss@cluster0.abc12.mongodb.net/mydb"

  - label: "Redis URI"
    type: kv
    input: "REDIS_URL=redis://:redispassword123@redis.internal.example.com:6379"
```

- [ ] **Step 8: Smoke-test current fixtures**

```bash
cargo build --release 2>/dev/null
uv run demo/demo.py 2>&1 | head -60
```

Expected: banner + level comparison + AI APIs + cloud sections visible, no Python errors, `[REDACTED-*]` tokens appear.

- [ ] **Step 9: Commit**

```bash
git add demo/examples/
git commit -m "feat(demo): add fixture files 00-06 (levels through databases)"
```

---

## Task 7: Fixture files 07–13

**Files:**
- Create: `demo/examples/07_package_managers.yaml` through `demo/examples/13_log_block.yaml`

- [ ] **Step 1: Create `07_package_managers.yaml`**

npm: exactly 36 alphanum chars after `npm_`.

```yaml
title: "Package Managers"
description: "npm, PyPI, and NuGet publish tokens"
level: minimal
examples:
  - label: "npm token"
    type: kv
    input: "NPM_TOKEN=npm_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"

  - label: "PyPI token"
    type: kv
    input: "PYPI_TOKEN=pypi-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDE"
```

- [ ] **Step 2: Create `08_monitoring.yaml`**

```yaml
title: "Monitoring"
description: "Sentry DSN contains an embedded secret key"
level: minimal
examples:
  - label: "Sentry DSN"
    type: kv
    input: "SENTRY_DSN=https://a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4@o123456.ingest.sentry.io/1234567"
```

- [ ] **Step 3: Create `09_generic.yaml`**

```yaml
title: "Generic Secrets"
description: "JWT tokens, private keys, bearer/basic auth headers, password fields"
level: minimal
examples:
  - label: "JWT token"
    type: kv
    input: "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

  - label: "Basic auth header"
    type: kv
    input: "Authorization: Basic dXNlcjpteXNlY3JldHBhc3N3b3Jk"

  - label: "Password field (config file)"
    type: kv
    input: 'password = "s3cr3t-Database-P4ss!"'

  - label: "Private key header"
    type: kv
    input: "-----BEGIN RSA PRIVATE KEY-----"

  - label: "Bearer token"
    type: kv
    input: "Authorization: Bearer ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmno"
```

- [ ] **Step 4: Create `10_paranoid_patterns.yaml`**

All `paranoid_only: true` patterns from enabled groups. Includes patterns that span multiple groups: `telegram_bot_token` (communication group) and `ssh_public_key` (generic group). Base64 inputs use pure alphanum to avoid `==` trailing the match boundary.

For `aws_secret_key` (`[A-Za-z0-9+/]{40}`): use 40 pure alphanumeric chars to avoid word-boundary issues with `+`/`/`.

```yaml
title: "Paranoid-Only Patterns"
description: "Secrets only matched at --level paranoid (paranoid_only: true across all enabled groups)"
level: paranoid
examples:
  - label: "Telegram bot token (communication group)"
    type: kv
    input: "TELEGRAM_BOT_TOKEN=1234567890:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi"

  - label: "SSH public key (generic group)"
    type: kv
    input: "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC3xyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij alice@laptop"

  - label: "AWS secret access key (paranoid group)"
    type: kv
    input: "AWS_SECRET_ACCESS_KEY=ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn"

  - label: "Datadog API key — 32 hex (paranoid group)"
    type: kv
    input: "DD_API_KEY=a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"

  - label: "Datadog app key — 40 hex (paranoid group)"
    type: kv
    input: "DD_APP_KEY=a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"

  - label: "Azure client secret — 34 chars (paranoid group)"
    type: kv
    input: "AZURE_CLIENT_SECRET=ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh"

  - label: "Twilio auth token — 32 hex (paranoid group)"
    type: kv
    input: "TWILIO_AUTH_TOKEN=a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"

  - label: "Cloudflare API key — 37 chars (paranoid group)"
    type: kv
    input: "CF_API_KEY=ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijk"

  - label: "Heroku API key — UUID format (paranoid group)"
    type: kv
    input: "HEROKU_API_KEY=a1b2c3d4-e5f6-a1b2-c3d4-e5f6a1b2c3d4"

  - label: "PagerDuty API key — 20 chars (paranoid group)"
    type: kv
    input: "PAGERDUTY_KEY=ABCDEFGHIJKLMNOPQRST"

  - label: "Base64 secret blob (paranoid group)"
    type: kv
    input: "SESSION_SECRET=ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrst"
```

- [ ] **Step 5: Create `11_pii.yaml`**

Passport and driver's license are `paranoid_only: true` — add per-example `level: paranoid` overrides.

```yaml
title: "PII (Personally Identifiable Information)"
description: "SSN, credit card, phone, IBAN, passport, driver's license — group disabled by default"
level: standard
disabled: true
examples:
  - label: "US Social Security Number"
    type: kv
    input: "ssn: 123-45-6789"

  - label: "Credit card number (Visa)"
    type: kv
    input: "card_number: 4111111111111111"

  - label: "US phone number"
    type: kv
    input: "phone: (555) 123-4567"

  - label: "IBAN"
    type: kv
    input: "iban: GB29NWBK60161331926819"

  - label: "Passport number (paranoid_only)"
    type: kv
    level: paranoid
    input: "passport: AB1234567"

  - label: "US driver's license (paranoid_only)"
    type: kv
    level: paranoid
    input: "drivers_license: A1234567"
```

- [ ] **Step 6: Create `12_structural.yaml`**

All structural features require `standard` or higher; `minimal` activates no structural features. Per-example level overrides demonstrate the activation level for each feature.

```yaml
title: "Structural Obfuscation"
description: "IPs, emails, containers, users (standard+) · hostnames, paths, high-entropy (paranoid)"
level: standard
examples:
  - label: "Internal IPv4 (standard)"
    type: kv
    level: standard
    input: "Connected to db at 192.168.10.50:5432"

  - label: "External IPv4 (standard)"
    type: kv
    level: standard
    input: "Outbound request to 8.8.8.8"

  - label: "Email address (standard)"
    type: kv
    level: standard
    input: "Sending invoice to alice@example.com"

  - label: "Docker container ID (standard)"
    type: kv
    level: standard
    input: "Container a1b2c3d4e5f6 restarted"

  - label: "Username (standard)"
    type: kv
    level: standard
    input: "user=alice authenticated successfully"

  - label: "Filesystem path (paranoid)"
    type: kv
    level: paranoid
    input: "Reading config from /home/alice/.config/myapp/config.json"

  - label: "Hostname (paranoid)"
    type: kv
    level: paranoid
    input: "Resolved prod-db-01.internal.example.com"

  - label: "High-entropy string (paranoid)"
    type: kv
    level: paranoid
    input: "session_id=aB3kL9mNpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUv"
```

- [ ] **Step 7: Create `13_log_block.yaml`**

```yaml
title: "Realistic Log Block"
description: "Mixed application log — secrets, IPs, users, container IDs, a DB URI"
level: standard
examples:
  - label: "Application startup log (standard)"
    type: block
    input: |
      2024-01-15T10:23:41Z INFO  [auth-service] starting up
      2024-01-15T10:23:41Z INFO  user=alice ip=192.168.10.5 container=a1b2c3d4e5f6 authenticated
      2024-01-15T10:23:42Z DEBUG ANTHROPIC_API_KEY=sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWXYZabcde
      2024-01-15T10:23:42Z DEBUG DATABASE_URL=postgres://alice:s3cr3tpassword@db.internal.example.com/prod
      2024-01-15T10:23:43Z ERROR failed to reach 10.0.0.50:5432 after 3 retries
      2024-01-15T10:23:43Z WARN  retrying via replica prod-db-02.internal.example.com
      2024-01-15T10:23:44Z INFO  session_token=Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.abc123

  - label: "Same log at paranoid level"
    type: block
    level: paranoid
    input: |
      2024-01-15T10:23:41Z INFO  [auth-service] starting up
      2024-01-15T10:23:41Z INFO  user=alice ip=192.168.10.5 container=a1b2c3d4e5f6 authenticated
      2024-01-15T10:23:42Z DEBUG ANTHROPIC_API_KEY=sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWXYZabcde
      2024-01-15T10:23:42Z DEBUG DATABASE_URL=postgres://alice:s3cr3tpassword@db.internal.example.com/prod
      2024-01-15T10:23:43Z ERROR failed to reach 10.0.0.50:5432 after 3 retries
      2024-01-15T10:23:43Z WARN  retrying via replica prod-db-02.internal.example.com
      2024-01-15T10:23:44Z INFO  session_token=Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.abc123
```

- [ ] **Step 8: Commit**

```bash
git add demo/examples/
git commit -m "feat(demo): add fixture files 07-13 (pkg managers through log block)"
```

---

## Task 8: Integration — full run and for-loop verification

**Files:** None

- [ ] **Step 1: Build the release binary**

```bash
cargo build --release
```

Expected: exits 0, `target/release/redact` exists.

- [ ] **Step 2: Run the full showcase**

```bash
uv run demo/demo.py 2>&1 | head -100
```

Expected: banner renders, all 14 fixture sections appear with bold-red `[REDACTED-*]` tokens. No Python tracebacks or identical before/after rows (which would indicate a fixture input doesn't match its pattern).

- [ ] **Step 3: Spot-check that every kv row shows redaction**

```bash
uv run demo/demo.py 2>&1 | grep -c "REDACTED"
```

Expected: at least 30 (one per kv example). If a row shows identical original and redacted, the fixture input doesn't match the pattern — compare input length against the Pattern length reference table at the top of this plan.

- [ ] **Step 4: Verify file mode**

```bash
echo "ANTHROPIC_API_KEY=sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWXYZabcde
user=alice ip=192.168.1.100" > /tmp/test_redact.txt

uv run demo/demo.py /tmp/test_redact.txt
```

Expected: rule with filename, Input panel, Redacted panel with bold-red tokens. No banner.

- [ ] **Step 5: Verify for-loop usage (clean output per invocation)**

```bash
for f in /tmp/test_redact.txt /tmp/test_redact.txt; do
  uv run demo/demo.py "$f"
  echo "---"
done
```

Expected: two clean before/after blocks separated by `---`, no banner noise between them.

- [ ] **Step 6: Verify --help**

```bash
uv run demo/demo.py --help
```

Expected: clean usage with epilog note that `--level` applies in file mode.

- [ ] **Step 7: Commit**

```bash
git add demo/
git commit -m "feat(demo): complete visual demo — showcase and file mode"
```
