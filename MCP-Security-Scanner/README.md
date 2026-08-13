# BlastScope

> **See your agent's blast radius before an attacker does.**

Security posture assessment for MCP and agentic AI installations. BlastScope assesses your **whole installation as a system** — not one server at a time — and catches the composition attacks, misconfigurations, and supply-chain risks that per-server scanners miss. Built by a practising CISO for the people who have to *govern* AI agents, not just run them.

Apache-2.0 · Python 3.10+ · local-first, no telemetry

<!-- Badges after first release: PyPI · CI · SARIF · OWASP LLM Top 10 · OWASP ASI 2026 -->
<!-- DEMO GIF: `blastscope scan` on a 3-server config -> CRITICAL trifecta -> fix one leg -> re-scan clean -->

---

## Why this exists

By 2026, MCP is the default way agents connect to tools — and it has become a proven attack surface. The pattern behind nearly every real incident is the same three ingredients in one agent: **access to private data, exposure to untrusted input, and a way to send data out.** Security researchers named it the *lethal trifecta*, and the documented breaches follow it precisely:

- A single malicious GitHub issue was enough to make an AI assistant with GitHub MCP access exfiltrate private repository contents — the user only asked it to review open issues.
- A support ticket containing embedded instructions caused a Cursor agent with privileged database credentials to query an internal tokens table and post the results back into the ticket thread.

Neither attack used malware or a stolen credential. The exploit was written in plain English, and the danger came from the *combination* of otherwise reasonable tools. As one analysis put it, the utility is the vulnerability: agents are useful precisely because they read your data, process outside input, and act on your behalf.

The wider picture reinforces it. Independent 2025–2026 assessments found command injection, path traversal, and SSRF across large fractions of scanned MCP servers; the official signed registry launched in Q1 2026 but most installs still come from unverified community sources and raw GitHub URLs; and named attack classes now include tool poisoning, rug pulls, tool shadowing, cross-server cascades, and confused-deputy OAuth flaws. OWASP codified agent goal hijack as ASI01 in its 2026 Top 10 for Agentic Applications.

Most tooling still asks *"is this one server misconfigured?"* BlastScope asks the question a security leader actually has to answer:

> **"If the model driving this installation is compromised by a single prompt injection, what is the total blast radius — and can I explain it to my board?"**

## What makes it different

| | Typical MCP scanner | BlastScope |
|---|---|---|
| Unit of analysis | one server / one config | **the whole installation, as a system** |
| Composition risk (cross-server chains) | rare or partial | **core feature — lethal trifecta + excessive agency** |
| Frameworks covered | MCP only | **MCP, OpenAI function-calling, LangChain** |
| Primary output | findings list | **severity posture + board-ready narrative + SARIF + AI-BOM** |
| Governance mapping | severity only | **OWASP LLM Top 10, OWASP ASI 2026, MITRE ATLAS, NIST AI RMF** |
| Org policy | — | **policy-as-code baselines with capability-combination bans** |
| Written for | AppSec engineers | **security leaders AND safe experimenters** |

Good per-server tools exist (mcp-scan, agent-audit, Snyk, and others) and BlastScope doesn't compete on raw rule count. Run one of those alongside it for deep per-server coverage. BlastScope owns the layer they don't: **what your installation can do as a whole.**

## Quick start

```bash
pipx install blastscope

# Scan whatever MCP clients are installed (auto-detected)
blastscope scan
```

```
BlastScope — Installation Assessment
──────────────────────────────────────────
Clients scanned : Claude Desktop, Cursor
Servers found   : 7        Tools declared: 43

  POSTURE:  CRITICAL          11 findings

  CRITICAL  Lethal trifecta present across installation
     private data ....... gmail (read_email)
     untrusted input .... web-fetch (fetch_url)
     exfiltration ....... hooks (post_webhook)
     A single prompt injection in any fetched page can read your
     email and post it to an attacker-controlled URL.
     Fix: sever one leg — isolate web-fetch, or allow-list the webhook.

  3 critical · 5 high · 6 medium · 1 low
```

Check a server **before** you install it — the pre-install seatbelt:

```bash
blastscope inspect npx:@vendor/mcp-server-foo
blastscope inspect https://mcp.vendor.example/sse
```

## What it detects

Deterministic, explainable, framework-mapped. Twelve risk classes: eight ship as versioned YAML rule packs (community-extensible), and four are engine-driven because they reason across the whole installation.

| ID | Risk class | Detects | Engine |
|----|-----------|---------|--------|
| R1 | Tool poisoning | Hidden/manipulative instructions in tool names & descriptions (incl. invisible Unicode, encoded blobs) | YAML |
| R2 | Injection surface | Tools that pipe untrusted external content (web, issues, tickets, email) into context | YAML |
| **R3** | **Lethal trifecta** | **Private data + untrusted input + exfil path, assessed across servers** | **composition** |
| R4 | Over-permissioning | Root/home filesystem grants, shell wrappers, arbitrary-URL tools | YAML |
| **R5** | **Rug pull** | **Tool definitions that silently change after approval (baseline hashing + drift)** | **baseline** |
| R7 | Credential exposure | Live secrets in configs, args, and URLs (entropy + known formats), redacted in output | YAML |
| R8 | Transport & auth | Unauthenticated remote servers, plaintext HTTP, weak session binding | YAML |
| R9 | Destructive actions | Irreversible tools (delete/send/pay/deploy) with no confirmation semantics | YAML |
| R10 | Supply chain | Unpinned versions, remote-URL execution, auto-confirm install flags | YAML |
| R11 | Exfiltration vectors | Caller-controlled URLs, writes to public locations | YAML |
| **R12** | **Excessive agency** | **Injection-to-destruction chains + aggregate blast-radius surface** | **composition** |

Findings map to **OWASP LLM Top 10, OWASP ASI 2026 (agentic), MITRE ATLAS, and NIST AI RMF** so one report speaks to engineers and risk committees at once.

## The composition engine (R3 + R12)

This is the core idea. BlastScope reduces every tool to the capabilities it grants — `private_data`, `untrusted_input`, `exfiltration`, `destructive` — then reasons over the union across all installed servers.

Three servers that each look harmless in isolation:

```
personal-notes   -> private_data
research          -> untrusted_input
notifier          -> exfiltration
```

…combine into a complete exfiltration pipeline. R3 fires **critical** with the full evidence chain, because severing any one leg breaks the attack. No per-server scanner can produce this finding — the risk doesn't live in any single server. Try it: `blastscope scan --config examples/trifecta_config.json`.

## For security teams

```bash
# Assess against an organisational policy baseline
blastscope scan --policy corp-policy.yaml

# CI gate + SARIF into the GitHub Security tab
blastscope scan --format sarif -o results.sarif --fail-on high

# Board-ready HTML narrative for your GRC pack
blastscope scan --format html -o ai-agent-risk.html

# Continuous rug-pull / drift monitoring
blastscope watch

# AI-BOM: a bill of materials for your agent's capability surface
blastscope export -o ai-bom.json
```

`--format html` produces a one-page narrative report: what the installation can do, the realistic attack path, and top remediations — written in risk-register language, not stack traces. Drop it into your GRC pack as-is.

![Sample boardroom report](examples/sample-boardroom-report.png)

**Policy-as-code.** Express rules generic scanning can't know — approved servers, banned capability *combinations*, mandatory hygiene:

```yaml
# corp-policy.yaml
version: 1
allow_servers: ["@modelcontextprotocol/*", "@internal/*"]
deny_capability_combinations:
  - [private_data, exfiltration]      # no trifecta components in one install
  - [untrusted_input, destructive]
require:
  version_pinning: true
  no_plaintext_secrets: true
  https_only: true
max_severity: medium                   # residual-risk ceiling
```

**GitHub Action.** Drop-in CI, findings upload to code scanning:

```yaml
- uses: ./action                       # or Kuizinass/blastscope-action@v1
  with:
    config: .mcp.json
    policy: mcp-policy.yaml
    fail-on: high
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: blastscope.sarif
```

**AI-BOM.** A machine-readable inventory of every server, tool, and classified capability with provenance — governance evidence for audits and DDQs, and a change-review tool: diff two exports to see exactly what an installation gained between approvals.

## Framework portability

The same rule engine and composition analysis run over any agent framework via a normalised capability model.

| Source | Status |
|--------|--------|
| MCP client configs (Claude Desktop/Code, Cursor, VS Code, Windsurf, `--config`) | done |
| MCP live handshake (executes server to enumerate real tools; asks first) | done |
| OpenAI function-calling schemas (`--openai-tools`) | done |
| LangChain tools — JSON export or live `BaseTool` objects in-process | done |
| CrewAI / AutoGen | planned |
| Adapter plugin API (bring your own framework) | documented |

The trifecta fires identically on an OpenAI tools file as on an MCP config — the risk is architectural, not protocol-specific.

## Optional LLM semantic pass

Deterministic rules catch known patterns. An **opt-in** LLM pass (`--llm`, your own `ANTHROPIC_API_KEY`) catches subtly manipulative language that regex can't — priority demands, disguised instructions, social engineering in tool descriptions. It sends **only tool names and descriptions**, never env vars, credentials, args, or URLs; every finding it produces is labelled `[heuristic]`; and deterministic detection never depends on it. Off unless you ask for it.

## Design principles

1. **Local-first, no telemetry, no phone-home.** Static analysis runs fully offline; nothing about your configuration is transmitted. The only network path is the explicit, opt-in `--llm` pass.
2. **Deterministic first.** Core detection is rule-based — same input, same findings.
3. **Handshake with consent.** Live inspection executes the server; BlastScope shows the exact command and asks first. Sandbox untrusted servers (the docs show how).
4. **Explainable or it doesn't ship.** Every finding cites its rule, evidence, remediation, and framework mapping. No black-box scores.
5. **Honest limitations.** BlastScope assesses capability surface and configuration, not server source code — pair it with a SAST/CVE scanner for the code layer. Capability classification is signal-based and can occasionally over- or under-tag; the evidence is always shown so you can judge. A clean result means "no known patterns detected", not "safe".

## Install

```bash
pipx install blastscope     # recommended
pip install blastscope      # or plain pip
```

From source:

```bash
git clone https://github.com/Kuizinass/AI-Projects.git
cd AI-Projects/MCP-Security-Scanner
pip install -e .
pytest
```

## Roadmap

- **v0.1** — static config scanning, R1/R4/R7/R9/R10, severity posture, terminal + JSON (done)
- **v0.5** — live handshake, composition engine (R3/R12), R2/R5/R8/R11, `inspect`, drift baselines, HTML report (done)
- **v1.0 (current)** — policy-as-code, SARIF + GitHub Action, OpenAI/LangChain adapters, optional LLM pass, AI-BOM export (done)
- **Next** — runtime guardrail mode reusing the rule engine, community rule registry, CrewAI/AutoGen adapters, signed rule packs, official MCP registry provenance checks

## Threat model

The full threat model — assumptions about attackers, clients, and servers, and what BlastScope can and cannot see — lives in [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md). Read it before trusting any scanner, including this one.

## Contributing

Rule packs are plain YAML — a new detection needs no engine code. Composition and capability logic live in `composition.py` / `capabilities.py`. Every rule must fire on the vulnerable fixture and stay silent on the clean one. See [`CONTRIBUTING.md`](CONTRIBUTING.md).

## About

Built by **Marius Poskus** — Global VP of Cybersecurity / CISO at an FCA-regulated FinTech, 14 years in security, and creator of **CTRL+ALT+DEFEND** (cybersecurity career education). I evaluate agentic AI the way I evaluate any privileged system, because that's what it is. BlastScope is that evaluation, automated.

## License

Apache-2.0

---

*BlastScope provides visibility, not guarantees. Use it alongside runtime controls, sandboxing, and human judgement.*
