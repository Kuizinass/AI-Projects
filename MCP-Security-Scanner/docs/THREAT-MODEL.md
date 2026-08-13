# BlastScope Threat Model

Read this before trusting any MCP scanner, including this one. A scanner you don't
understand the limits of is a false sense of security.

## What we're defending

An MCP or agentic-AI *installation*: one or more clients (Claude Desktop/Code,
Cursor, VS Code, Windsurf) each configured with one or more servers, every server
exposing tools the model can call. The asset at risk is everything those tools can
reach — files, mailboxes, databases, credentials, money, and outbound network.

## Attacker model

We assume an attacker who **cannot** run code on your machine directly but **can**:

1. **Influence content your agent reads.** A web page, GitHub issue, support
   ticket, email, PR comment, or document — anything an untrusted-input tool pulls
   into context. This is the primary vector; the exploit is a sentence, not a binary.
2. **Publish or compromise an MCP server.** Via community registries, raw GitHub
   URLs, or a supply-chain compromise of a legitimate package.
3. **Change a server's tool definitions after you approved them** (rug pull),
   especially for remote/SSE servers.
4. **Sit on the network path** to a plaintext or unauthenticated remote server.

We do **not** assume an attacker with existing local code execution or root — if
they have that, MCP configuration is not your problem.

## The core risk: composition

The defining insight is that individual servers can each be reasonable while their
*combination* is catastrophic. The lethal trifecta — private-data access, untrusted
input, and an exfiltration path in one agent — turns a single prompt injection into
full data theft with no malware and no stolen credentials. Real 2025–2026 incidents
(GitHub-issue exfiltration, Supabase/Cursor support-ticket data theft) followed this
pattern exactly. BlastScope's reason to exist is assessing that composition, which
per-server tools structurally cannot see.

## What BlastScope CAN see

- Tool poisoning signals in names/descriptions, including invisible Unicode and
  encoded blobs (R1).
- Untrusted-input surfaces (R2) and exfiltration primitives (R11).
- Cross-server lethal trifecta (R3) and injection-to-destruction chains (R12).
- Post-approval definition drift, given a baseline (R5).
- Over-permissioning, plaintext secrets, weak transport, destructive tools,
  supply-chain hygiene (R4/R7/R8/R9/R10).
- Aggregate capability surface, exported as an AI-BOM.
- Violations of your organisational policy (approved servers, banned capability
  combinations, mandatory hygiene).

## What BlastScope CANNOT see (limitations)

- **Server source code.** We assess declared/enumerated definitions and config, not
  the implementation. A server whose description is benign but whose *code* is
  malicious will pass description-level checks. Pair BlastScope with a SAST/CVE
  scanner and registry provenance checks for the code and supply-chain layer.
- **Runtime behaviour.** This is assessment, not enforcement. A tool that behaves
  differently at runtime than its definition suggests is out of scope until the
  planned runtime-guardrail mode lands.
- **Semantic nuance, deterministically.** Capability classification is signal-based
  (keywords + structure). It can over-tag ("post a message" looking like private
  data) or under-tag a cleverly-worded tool. Evidence is always shown so you can
  judge; the optional LLM pass narrows this gap but is heuristic.
- **Model-layer prompt injection defence.** BlastScope reduces the *surface* for
  injection; it cannot stop injection inside the model. That is an unsolved problem
  at the model layer.
- **Zero-day attack classes** not yet encoded as rules or capability signals.

## Trust boundaries in the tool itself

- **Local-first.** Static analysis never transmits your configuration. The only
  outbound path is the explicit, opt-in `--llm` pass, which sends *only* tool names
  and descriptions (never env, args, URLs, or secrets) to the Anthropic API with
  your own key.
- **Live handshake executes servers.** `--live` and `inspect` launch the server to
  enumerate real tools. That is code execution; BlastScope shows the exact command
  and requires consent. Scan untrusted servers in a sandbox/VM/container.
- **No auto-remediation.** BlastScope never edits your configs. Every fix is advice
  you apply yourself, so the tool can never make your posture worse.

## How to use this responsibly

BlastScope is one layer. A complete posture also needs: registry provenance and
signing checks, per-server code scanning, least-privilege scoping at the client,
runtime monitoring, and human review of anything touching sensitive data. Treat a
clean BlastScope result as "no known patterns detected", never as "safe".
