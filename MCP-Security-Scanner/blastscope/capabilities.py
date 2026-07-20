"""Capability taxonomy — the foundation of composition analysis.

Per-server rules ask "is this one thing risky?". Composition analysis asks
"what can this INSTALLATION do as a whole?". To answer that we first reduce every
tool down to the capabilities it grants, then reason over the union of capabilities
across all servers.

Four capability axes matter for the trifecta and blast-radius logic:

  PRIVATE_DATA   — can read data the user would not want exfiltrated
  UNTRUSTED_IN   — can pull attacker-influenceable content into model context
  EXFIL          — can send data to an attacker-controllable destination
  DESTRUCTIVE    — can take irreversible real-world action

Classification is deterministic and evidence-bearing: every assigned capability
records why it was assigned, so findings can cite the specific tool and signal.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum

from blastscope.models import ServerConfig, ToolDefinition


class Capability(str, Enum):
    PRIVATE_DATA = "private_data"
    UNTRUSTED_IN = "untrusted_input"
    EXFIL = "exfiltration"
    DESTRUCTIVE = "destructive"


# Signal patterns per capability. Matched against tool name + description + server name.
# Kept intentionally conservative — a false "capable" is better than a false "safe"
# for the trifecta, but we still want signal, not noise.
_SIGNALS: dict[Capability, list[str]] = {
    Capability.PRIVATE_DATA: [
        r"\b(read|get|list|fetch|search|query|load|export)\b.{0,30}"
        r"\b(email|mail|inbox|message|file|document|contact|calendar|note|secret|"
        r"credential|token|key|password|database|record|customer)\b",
        r"\b(gmail|outlook|imap|filesystem|file[-_]?system|obsidian|notion|slack|"
        r"drive|dropbox|s3|vault|1password|keychain|sqlite|postgres|mysql|mongo)\b",
        r"\bread[-_]?file\b|\bget[-_]?secret\b|\blist[-_]?files?\b",
    ],
    Capability.UNTRUSTED_IN: [
        r"\b(fetch|browse|scrape|crawl|read|download|open)\b.{0,20}"
        r"\b(url|web|page|site|http|internet|link|feed|rss)\b",
        r"\b(web[-_]?fetch|web[-_]?search|browser|puppeteer|playwright|fetch[-_]?url|"
        r"http[-_]?get|curl)\b",
        r"\breceive\b.{0,20}\b(email|message|webhook|comment|issue|ticket)\b",
        r"\b(read|get|list|fetch)\b.{0,20}\b(issue|ticket|pull[-_]?request|comment|review)\b",
    ],
    Capability.EXFIL: [
        r"\b(post|put|send|upload|write|push|publish|export)\b.{0,25}"
        r"\b(url|http|webhook|endpoint|remote|server|api|external)\b",
        r"\b(send|post)\b.{0,15}\b(email|mail|message|slack|discord|tweet|sms|dm)\b",
        r"\b(webhook|http[-_]?post|http[-_]?put|upload[-_]?file|post[-_]?message|"
        r"send[-_]?email|send[-_]?payment|create[-_]?gist|publish)\b",
        r"arbitrary\s+(url|host|endpoint)|any\s+(url|host|endpoint)",
        r"sends?\s+(a\s+)?(payment|funds|money|data|file)\s+to\s+(any|an?\s+)",
    ],
    Capability.DESTRUCTIVE: [
        r"\b(delete|drop|truncate|destroy|purge|wipe|remove|erase)\b",
        r"\b(pay|transfer|charge|refund|send[-_]?payment|send[-_]?funds)\b",
        r"\b(deploy|execute|run[-_]?command|shell|exec|eval|terminate|shutdown)\b",
        r"\boverwrite\b|\bforce[-_]?push\b",
    ],
}

_COMPILED = {cap: [re.compile(p, re.IGNORECASE) for p in pats] for cap, pats in _SIGNALS.items()}


@dataclass
class CapabilityEvidence:
    capability: Capability
    tool: str
    signal: str          # the text that triggered classification


@dataclass
class ServerCapabilities:
    server: str
    capabilities: set[Capability] = field(default_factory=set)
    evidence: list[CapabilityEvidence] = field(default_factory=list)


def _classify_text(text: str, tool_name: str, out: ServerCapabilities) -> None:
    """A single tool can grant multiple capabilities — check every axis independently."""
    for cap, patterns in _COMPILED.items():
        already = any(e.capability == cap and e.tool == tool_name for e in out.evidence)
        if already:
            continue
        for pat in patterns:
            m = pat.search(text)
            if m:
                out.capabilities.add(cap)
                out.evidence.append(CapabilityEvidence(cap, tool_name, _clip(m.group(0))))
                break


def _clip(s: str, n: int = 60) -> str:
    s = " ".join(s.split())
    return s if len(s) <= n else s[: n - 1] + "…"


def classify_server(server: ServerConfig) -> ServerCapabilities:
    caps = ServerCapabilities(server=server.name)

    # Server name / package itself is a strong signal (e.g. "gmail", "filesystem")
    pkg_hint = " ".join([server.name, server.command] + server.args)
    _classify_text(pkg_hint, server.name, caps)

    for tool in server.tools:
        blob = f"{tool.name} {tool.description}"
        _classify_text(blob, tool.name or "(unnamed)", caps)

    return caps


def classify_installation(servers: list[ServerConfig]) -> list[ServerCapabilities]:
    return [classify_server(s) for s in servers]
