# BlastScope Usage Guide

A practical, task-oriented guide to scanning MCP and agentic AI installations with
BlastScope. For the design rationale and limits, read the [threat model](THREAT-MODEL.md).

---

## Table of contents

1. [Install](#1-install)
2. [Your first scan](#2-your-first-scan)
3. [Understanding the output](#3-understanding-the-output)
4. [Command reference](#4-command-reference)
5. [Checking a server before you install it](#5-checking-a-server-before-you-install-it)
6. [Live inspection (executing servers safely)](#6-live-inspection)
7. [Policy as code for teams](#7-policy-as-code)
8. [CI/CD integration (SARIF + GitHub Action)](#8-cicd-integration)
9. [Continuous drift monitoring (rug pulls)](#9-continuous-drift-monitoring)
10. [Non-MCP frameworks (OpenAI, LangChain)](#10-non-mcp-frameworks)
11. [AI-BOM: your agent capability inventory](#11-ai-bom)
12. [The optional LLM pass](#12-the-optional-llm-pass)
13. [Writing custom rules](#13-writing-custom-rules)
14. [Common workflows](#14-common-workflows)
15. [Troubleshooting](#15-troubleshooting)

---

## 1. Install

```bash
pipx install blastscope       # recommended — isolated environment
pip install blastscope        # or plain pip
```

From source (for contributing or running the latest):

```bash
git clone https://github.com/Kuizinass/AI-Projects.git
cd AI-Projects/MCP-Security-Scanner
pip install -e .
pytest                        # 41 tests should pass
```

Requirements: Python 3.10+. No other system dependencies for the default
(offline) path.

Verify:

```bash
blastscope --version
```

---

## 2. Your first scan

Zero configuration. BlastScope auto-detects MCP clients installed on your machine
(Claude Desktop, Claude Code, Cursor, VS Code, Windsurf) and scans them:

```bash
blastscope scan
```

To scan a specific config file instead of auto-detecting:

```bash
blastscope scan --config ~/Library/Application\ Support/Claude/claude_desktop_config.json
```

Try it against the bundled example that demonstrates the headline feature — three
individually-harmless servers that together form an exfiltration pipeline:

```bash
blastscope scan --config examples/trifecta_config.json
```

---

## 3. Understanding the output

A scan produces four things:

**Posture** — the headline label, derived purely from the highest-severity finding
present: `CRITICAL`, `HIGH RISK`, `MEDIUM RISK`, `LOW RISK`, or `CLEAN`. It is a
summary of the findings, not a separate score.

**Findings** — each carries:
- a **severity** (critical / high / medium / low)
- the **server** and **location** it was found in
- **evidence** (redacted where it contains secrets)
- **why** it matters, in plain English
- a **fix**
- **framework mappings** (OWASP LLM Top 10, OWASP ASI 2026, MITRE ATLAS, NIST AI RMF)

**Severity counts** — the breakdown across all findings.

**Verdict** — a one-line human summary pointing at the worst issue.

Rule IDs tell you the risk class at a glance: `BS-R3-001` is risk class R3 (lethal
trifecta), `BS-POL-005` is a policy violation, `BS-R5-001` is a rug-pull drift
finding, `BS-LLM-001` is a heuristic finding from the optional LLM pass.

A `CLEAN` result means *no known patterns were detected* — not a guarantee of
safety. See the threat model for what BlastScope cannot see.

---

## 4. Command reference

| Command | Purpose |
|---------|---------|
| `scan` | Assess an installation (auto-detected or via `--config`). The main command. |
| `inspect` | Assess a single server *before* you add it to a client. |
| `watch` | One-shot drift check against a recorded baseline (for scheduling). |
| `export` | Emit an AI-BOM: the full capability surface as JSON. |
| `rules` | List loaded detection rules. |

### `scan` options

| Option | Effect |
|--------|--------|
| `--config PATH` | Scan a specific config file (repeatable). Disables auto-discovery. |
| `--manifest PATH` | Also scan a standalone tool-manifest JSON (repeatable). |
| `--openai-tools PATH` | Also assess an OpenAI function-calling tools JSON (repeatable). |
| `--langchain-export PATH` | Also assess a LangChain tools JSON export (repeatable). |
| `--rules-dir PATH` | Load extra YAML rule packs from a directory (repeatable). |
| `--live` | Handshake with stdio servers to enumerate real tools (executes them; asks first). |
| `--policy PATH` | Evaluate against an organisational policy YAML. |
| `--llm` | Opt-in LLM semantic pass (needs `ANTHROPIC_API_KEY`). |
| `--format` | `terminal` (default), `json`, `html`, or `sarif`. |
| `-o, --output PATH` | Write output to a file. |
| `--fail-on` | Exit non-zero if any finding is at/above this severity (CI gate). |
| `--baseline` | Record/update the rug-pull baseline during this scan. |
| `--baseline-path PATH` | Custom baseline file location. |
| `--summary-only` | Posture and verdict only, no per-finding detail. |

---

## 5. Checking a server before you install it

The pre-install seatbelt. Assess a server *before* it ever touches your config:

```bash
# A package you're about to add
blastscope inspect npx:@vendor/mcp-server-foo
blastscope inspect uvx:some-mcp-server

# A remote endpoint
blastscope inspect https://mcp.vendor.example/sse

# A config or manifest file someone sent you
blastscope inspect ./their-config.json
```

By default, `inspect` will offer to handshake with a launchable server to read its
real tools. To assess only what's declared, without executing anything:

```bash
blastscope inspect npx:@vendor/mcp-server-foo --no-live
```

Output formats mirror `scan` (`terminal`, `json`, `html`).

---

## 6. Live inspection

Most MCP servers don't declare their tools in config — the real definitions only
appear when a client handshakes with the running server. `--live` does that
handshake so BlastScope assesses the *actual* tools, not just the config.

```bash
blastscope scan --live
```

**This executes the server.** BlastScope shows you the exact command and asks for
confirmation before launching anything:

```
Live inspection will EXECUTE this server:
  npx @vendor/mcp-server-foo
Only do this for servers you're willing to run. Sandbox untrusted ones.
Proceed? [y/N]:
```

**For untrusted servers, sandbox first.** Run BlastScope inside a throwaway
container or VM so a hostile server can't touch your real environment:

```bash
docker run --rm -it -v "$PWD:/work" -w /work python:3.12-slim bash
pip install blastscope
blastscope scan --config suspicious-config.json --live
```

Static analysis (without `--live`) never executes anything and is always safe to run.

---

## 7. Policy as code

Per-server rules answer "what is risky?". Policy answers "what does *our
organisation* allow?". Express your standards once, enforce them everywhere.

Create `corp-policy.yaml`:

```yaml
version: 1

# Only these servers may be installed. Globs match name, command, url, and args.
allow_servers:
  - "@modelcontextprotocol/*"
  - "@internal/*"

# Always banned, regardless of the allow list.
deny_servers:
  - "*pastebin*"
  - "*anonymous*"

# Capability combinations that must never co-exist in one installation.
# This is how you forbid the lethal trifecta at policy level.
deny_capability_combinations:
  - [private_data, exfiltration]
  - [untrusted_input, destructive]

require:
  version_pinning: true        # npx/uvx packages must pin an exact version
  no_plaintext_secrets: true   # any plaintext credential is a violation
  https_only: true             # remote servers must use TLS

max_severity: medium           # residual-risk ceiling; anything above is a violation
```

Run it:

```bash
blastscope scan --policy corp-policy.yaml
```

Policy violations appear as findings with `BS-POL-###` ids alongside the technical
findings. The four capability values you can reference in combinations are
`private_data`, `untrusted_input`, `exfiltration`, and `destructive`.

---

## 8. CI/CD integration

### SARIF into the GitHub Security tab

```bash
blastscope scan --config .mcp.json --format sarif -o blastscope.sarif --fail-on high
```

`--fail-on high` makes the command exit non-zero when any finding is high or
critical, which fails the build.

### GitHub Action

A composite action ships in `action/action.yml`. Example workflow
(`.github/workflows/mcp-security.yml`):

```yaml
name: MCP security scan
on:
  pull_request:
    paths: [".mcp.json", ".cursor/**", ".vscode/mcp.json", "mcp-policy.yaml"]
  workflow_dispatch:

jobs:
  blastscope:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read
    steps:
      - uses: actions/checkout@v4
      - name: BlastScope scan
        uses: ./action
        with:
          config: .mcp.json
          policy: mcp-policy.yaml
          fail-on: high
      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: blastscope.sarif
```

The `if: always()` ensures findings upload even when the gate fails the job, so
developers see them in the Security tab.

### Other CI systems

Any system can gate on the exit code:

```bash
blastscope scan --config .mcp.json --fail-on high --summary-only || exit 1
```

---

## 9. Continuous drift monitoring

Rug pulls — tool definitions silently changing after you approved them — are one of
the hardest MCP risks to catch by eye. BlastScope baselines every tool definition
and flags drift.

Record a baseline (do this once, when you trust the current state):

```bash
blastscope scan --baseline
```

Then check for drift on a schedule. `watch` is a one-shot check designed to be
wrapped by cron, a systemd timer, or a CI job:

```bash
blastscope watch
```

It exits non-zero and lists the changed tools if any definition has changed since
the baseline. Example cron entry (daily at 8am):

```
0 8 * * *  blastscope watch || notify-send "BlastScope: MCP definition drift detected"
```

Use `--baseline-path` to keep separate baselines for separate environments.

---

## 10. Non-MCP frameworks

The same detection engine and composition analysis run on other agent frameworks,
because the risks are architectural, not protocol-specific.

**OpenAI function-calling** — export your tools array to JSON and:

```bash
blastscope scan --openai-tools my_agent_tools.json
```

**LangChain** — export tool metadata to JSON:

```bash
blastscope scan --langchain-export langchain_tools.json
```

**LangChain, live in your own code** — assess an agent's tools in-process:

```python
from blastscope.adapters.langchain_tools import from_langchain_tools
from blastscope.engine import load_rules, scan_installation
from blastscope.models import Installation
from blastscope.scoring import assess

server = from_langchain_tools(my_agent.tools, name="support-agent")
inst = Installation(servers=[server])
findings = scan_installation(inst, load_rules())
print(assess(findings).posture)
```

You can mix sources in one scan — e.g. `--config` plus `--openai-tools` — to assess
a mixed-framework deployment as a single installation.

---

## 11. AI-BOM

An AI-BOM (AI Bill of Materials) is a machine-readable inventory of everything your
agents can do: every server, every tool, and every classified capability with the
evidence for why it was classified that way.

```bash
blastscope export -o ai-bom.json
```

Use it for:

- **Audits and vendor DDQs** — attach it as evidence of what your agents can reach.
- **Change review** — diff two exports to see exactly what an installation gained
  between approvals:

  ```bash
  blastscope export -o before.json
  # ... someone adds a server ...
  blastscope export -o after.json
  diff <(jq -S . before.json) <(jq -S . after.json)
  ```

- **Governance registers** — the `capability_union` field summarises total reach in
  one place.

---

## 12. The optional LLM pass

Deterministic rules catch known patterns. The optional LLM pass catches subtly
manipulative language they can't — priority demands ("always call this first"),
disguised instructions, social engineering in tool descriptions.

It is **off by default**. To enable it:

```bash
export ANTHROPIC_API_KEY=sk-ant-...
blastscope scan --llm
```

What it does and doesn't do:

- Sends **only tool names and descriptions** to the Anthropic API. Never env vars,
  arguments, URLs, or secrets. (There is a test enforcing this.)
- Uses **your own** API key — nothing is bundled or proxied.
- Labels every finding it produces `[heuristic]` — verify by reading the flagged
  description yourself.
- Never affects deterministic detection. Rules run identically with or without it.

If you omit `--llm` or don't set a key, BlastScope runs fully offline.

---

## 13. Writing custom rules

Detection rules are plain YAML — adding one needs no engine code. Point BlastScope
at a directory of your own packs:

```bash
blastscope scan --rules-dir ./my-rules
```

A minimal rule:

```yaml
rules:
  - id: BS-R7-500                # BS-<risk class>-<number>, must be unique
    risk_class: R7
    severity: high               # critical | high | medium | low | info
    title: Internal token format in config
    applies_to: env_value        # which field to inspect
    detector: regex              # regex | builtin
    pattern: 'CORP-[A-Z0-9]{32}'
    redact: true                 # redact the match in output (use for secrets)
    explanation: An internal CORP token is stored in plaintext.
    remediation: Move it to the OS keychain and rotate it.
    mappings:                    # every rule maps to at least one framework
      owasp_llm10: "LLM02 Sensitive Information Disclosure"
      nist_ai_rmf: "GOVERN"
```

Field selectors for `applies_to`: `command`, `server_name`, `url`, `arg`,
`env_value`, `env_pair`, `tool_name`, `tool_description`, `tool_annotations`,
`any_text`. Builtin detectors include `high_entropy_secret`, `zero_width_unicode`,
`base64_blob`, and `broad_fs_path`.

List everything currently loaded:

```bash
blastscope rules --rules-dir ./my-rules
```

Composition (R3/R12), rug-pull (R5), and capability logic live in Python
(`composition.py`, `baseline.py`, `capabilities.py`), not YAML, because they reason
across the whole installation. See `CONTRIBUTING.md` to extend those.

---

## 14. Common workflows

**"I'm about to try a new MCP server I found online."**
```bash
blastscope inspect npx:@vendor/the-server --no-live   # static first
# if it looks reasonable and you want the real tools, in a sandbox:
blastscope inspect npx:@vendor/the-server              # will ask before executing
```

**"I want to check my own machine right now."**
```bash
blastscope scan
```

**"I run security for a team and want a standard enforced."**
```bash
# once: agree a policy, commit corp-policy.yaml to a shared repo
# in CI on every change to MCP configs:
blastscope scan --config .mcp.json --policy corp-policy.yaml \
  --format sarif -o blastscope.sarif --fail-on high
```

**"I need something to show a risk committee."**
```bash
blastscope scan --format html -o ai-agent-risk.html
```

**"I want to be told if a server changes under me."**
```bash
blastscope scan --baseline          # establish trust baseline
# then, scheduled:
blastscope watch
```

**"I need audit evidence of what our agents can do."**
```bash
blastscope export -o ai-bom.json
```

---

## 15. Troubleshooting

**"No MCP servers found."**
BlastScope didn't find a known client config. Point it at your config explicitly:
`blastscope scan --config <path>`. Config locations vary by OS and client; on macOS
Claude Desktop lives at
`~/Library/Application Support/Claude/claude_desktop_config.json`.

**Live inspection times out or errors.**
The server may need environment variables (API keys) set in its config `env` block
to start, or it may not be a stdio server. Static analysis still runs; only the
live enumeration is skipped, and BlastScope tells you which servers it couldn't
reach.

**A finding looks like a false positive.**
Capability classification is signal-based and occasionally over-tags (e.g. "post a
message" reading as private-data access). The evidence is always shown so you can
judge. If a deterministic rule is wrong, the rule ID in the output tells you exactly
which pattern fired — tune or override it with your own `--rules-dir` pack.

**`pip install -e .` fails with a hatchling metadata error.**
Update your build backend: `pip install -U hatchling`, then retry.

**The LLM pass is skipped.**
It needs `ANTHROPIC_API_KEY` in your environment and the `--llm` flag. Without
both, BlastScope runs its deterministic analysis only (which is the default and is
fully offline).

---

*Questions, bugs, or a detection BlastScope missed? Open an issue. A missed
detection with a sample config is the single most useful thing you can contribute.*