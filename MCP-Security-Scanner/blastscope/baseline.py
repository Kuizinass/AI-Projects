"""R5 — rug-pull detection via definition baselining.

MCP tool definitions can change after you approve them, especially for remote
servers. A server can present benign tools at install time, then swap in a
malicious description later (the "rug pull"). We defend against this by recording
a content hash of every tool definition on first sight, then diffing on every
subsequent scan.

Baseline lives at ~/.blastscope/baseline.json by default. It is local-only.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from blastscope.models import Finding, Installation, ServerConfig, Severity

DEFAULT_BASELINE = Path.home() / ".blastscope" / "baseline.json"


def _tool_fingerprint(server: ServerConfig) -> dict[str, str]:
    """Map of tool-name -> hash of its security-relevant definition."""
    fp: dict[str, str] = {}
    for t in server.tools:
        blob = json.dumps({
            "name": t.name,
            "description": t.description,
            "input_schema": t.input_schema,
            "annotations": t.annotations,
        }, sort_keys=True, ensure_ascii=False)
        fp[t.name] = hashlib.sha256(blob.encode("utf-8")).hexdigest()
    return fp


def _server_key(server: ServerConfig) -> str:
    """Stable identity for a server across scans, independent of which file it
    was found in. Keyed on server name plus command/url identity."""
    identity = server.url or " ".join([server.command] + server.args) or server.name
    return f"{server.name}::{identity}"


def load_baseline(path: Path | None = None) -> dict:
    path = path or DEFAULT_BASELINE
    if path.is_file():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return {}
    return {}


def save_baseline(baseline: dict, path: Path | None = None) -> None:
    path = path or DEFAULT_BASELINE
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(baseline, indent=2), encoding="utf-8")


def check_and_update(inst: Installation, path: Path | None = None,
                     update: bool = True) -> list[Finding]:
    """Compare current definitions against the baseline; return drift findings."""
    baseline = load_baseline(path)
    servers_bl = baseline.setdefault("servers", {})
    findings: list[Finding] = []
    now = datetime.now(timezone.utc).isoformat()

    for server in inst.servers:
        if not server.tools:
            continue
        key = _server_key(server)
        current = _tool_fingerprint(server)
        record = servers_bl.get(key)

        if record is None:
            servers_bl[key] = {"tools": current, "first_seen": now, "last_seen": now}
            continue

        prior = record.get("tools", {})
        for tool_name, cur_hash in current.items():
            if tool_name in prior and prior[tool_name] != cur_hash:
                findings.append(Finding(
                    rule_id="BS-R5-001",
                    risk_class="R5",
                    severity=Severity.HIGH,
                    title="Tool definition changed since baseline (possible rug pull)",
                    server=server.name,
                    location=f"tools.{tool_name}",
                    evidence=f"definition hash changed since {record.get('first_seen', 'baseline')}",
                    explanation=(
                        "A tool's definition changed after it was first recorded. "
                        "Benign updates happen, but silent post-approval changes are "
                        "also how a trusted server turns malicious. Review the diff "
                        "before trusting this tool again."
                    ),
                    remediation=(
                        "Inspect what changed. If you did not expect an update, treat "
                        "the server as compromised. Pin remote servers to a version."
                    ),
                    mappings={"owasp_llm10": "LLM03 Supply Chain",
                              "mitre_atlas": "AML.T0010", "nist_ai_rmf": "MEASURE"},
                ))
            elif tool_name not in prior:
                findings.append(Finding(
                    rule_id="BS-R5-002",
                    risk_class="R5",
                    severity=Severity.MEDIUM,
                    title="New tool appeared on known server since baseline",
                    server=server.name,
                    location=f"tools.{tool_name}",
                    evidence=f"tool '{tool_name}' not present at baseline",
                    explanation=(
                        "A server that was already approved has grown a new tool. "
                        "Capability creep on a trusted server deserves a look."
                    ),
                    remediation="Confirm the new tool is expected before relying on this server.",
                    mappings={"owasp_llm10": "LLM03 Supply Chain", "nist_ai_rmf": "MEASURE"},
                ))

        if update:
            record["tools"] = current
            record["last_seen"] = now

    if update:
        save_baseline(baseline, path)

    return findings
