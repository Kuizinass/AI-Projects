"""Rule engine.

Rules live in YAML packs (blastscope/rules/*.yaml plus any user-supplied
directory). Each rule selects fields from the normalised model and applies a
detector. Deterministic by design: same input, same findings, no model in the loop.

Rule schema:
  id: BS-R7-001
  risk_class: R7
  severity: high
  title: ...
  explanation: ...
  remediation: ...
  mappings: {owasp_llm10: "LLM02", mitre_atlas: "AML.T0057", nist_ai_rmf: "GOVERN"}
  applies_to: env_value | env_pair | arg | command | server_name | url |
              tool_name | tool_description | tool_annotations | any_text
  detector: regex | builtin
  pattern: <regex>              (detector: regex)
  builtin: <registered name>    (detector: builtin)
"""
from __future__ import annotations

import base64
import math
import re
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Callable, Iterator

import yaml

from blastscope.models import Finding, Installation, ServerConfig, Severity

# ---------------------------------------------------------------- field selectors

def _iter_fields(server: ServerConfig, selector: str) -> Iterator[tuple[str, str]]:
    """Yield (location, value) pairs for a selector."""
    if selector in ("command", "any_text") and server.command:
        yield "command", server.command
    if selector in ("server_name", "any_text") and server.name:
        yield "server", server.name
    if selector in ("url", "any_text") and server.url:
        yield "url", server.url
    if selector in ("arg", "any_text"):
        for i, a in enumerate(server.args):
            yield f"args[{i}]", a
    if selector in ("env_value", "any_text"):
        for k, v in server.env.items():
            yield f"env.{k}", v
    if selector == "env_pair":
        for k, v in server.env.items():
            yield f"env.{k}", f"{k}={v}"
    for t in server.tools:
        if selector in ("tool_name", "any_text") and t.name:
            yield f"tools.{t.name}", t.name
        if selector in ("tool_description", "any_text") and t.description:
            yield f"tools.{t.name}.description", t.description
        if selector == "tool_annotations":
            yield f"tools.{t.name}.annotations", yaml.safe_dump(t.annotations or {})


# ---------------------------------------------------------------- builtin detectors
# A builtin returns an evidence string when it fires, else None.
Builtin = Callable[[str], "str | None"]
_BUILTINS: dict[str, Builtin] = {}


def builtin(name: str) -> Callable[[Builtin], Builtin]:
    def deco(fn: Builtin) -> Builtin:
        _BUILTINS[name] = fn
        return fn
    return deco


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {c: s.count(c) for c in set(s)}
    return -sum((n / len(s)) * math.log2(n / len(s)) for n in freq.values())


@builtin("high_entropy_secret")
def _high_entropy(value: str) -> str | None:
    """Long, high-entropy token that looks like a credential, not a path or URL."""
    v = value.strip()
    if len(v) < 20 or len(v) > 512:
        return None
    if v.startswith(("http://", "https://", "/", "~", "./", "${", "$")):
        return None
    if "/" in v and v.count("/") > 2:  # path-like
        return None
    if " " in v:
        return None
    if _shannon_entropy(v) >= 4.0:
        return _redact(v)
    return None


@builtin("zero_width_unicode")
def _zero_width(value: str) -> str | None:
    suspicious = [c for c in value if c in "\u200b\u200c\u200d\u2060\ufeff\u00ad"
                  or "\ue000" <= c <= "\uf8ff"]
    if suspicious:
        return f"{len(suspicious)} invisible/private-use character(s) detected"
    return None


@builtin("base64_blob")
def _base64_blob(value: str) -> str | None:
    """Long base64 runs inside descriptive text — classic hidden-payload carrier."""
    for m in re.finditer(r"[A-Za-z0-9+/]{40,}={0,2}", value):
        chunk = m.group(0)
        try:
            decoded = base64.b64decode(chunk + "=" * (-len(chunk) % 4), validate=False)
            if sum(32 <= b < 127 for b in decoded) / max(len(decoded), 1) > 0.85:
                return f"decodable base64 blob ({len(chunk)} chars) embedded in text"
        except Exception:
            continue
    return None


@builtin("broad_fs_path")
def _broad_fs(value: str) -> str | None:
    v = value.strip().rstrip("/\\") or "/"
    roots = {"", "/", "~", "/home", "/users", "/etc", "/var", "c:", "c:\\users",
             "/system", "/library"}
    if v.lower() in roots or re.fullmatch(r"[a-z]:", v.lower()):
        return f"grants access at or near filesystem root: '{value}'"
    home = str(Path.home())
    if v in (home, home.rstrip("/")):
        return f"grants access to entire home directory: '{value}'"
    return None


@builtin("unpinned_package")
def _unpinned(value: str) -> str | None:
    if re.search(r"@latest$", value):
        return f"'{value}' — floating @latest tag"
    # npx/uvx package with no version specifier at all
    if re.fullmatch(r"(@[\w.-]+/)?[\w.-]+", value) and not re.search(r"@\d", value):
        return None  # bare name alone is handled at arg-context level by regex rules
    return None


# ---------------------------------------------------------------- engine

@dataclass
class Rule:
    id: str
    risk_class: str
    severity: Severity
    title: str
    explanation: str
    remediation: str
    applies_to: str
    detector: str
    pattern: str = ""
    builtin: str = ""
    mappings: dict = None
    redact: bool = False

    _compiled: "re.Pattern | None" = None

    def compile(self) -> None:
        if self.detector == "regex":
            self._compiled = re.compile(self.pattern, re.IGNORECASE)

    def check(self, value: str) -> str | None:
        if self.detector == "regex":
            m = self._compiled.search(value)
            if m:
                return _redact(m.group(0)) if self.redact else _clip(m.group(0))
            return None
        if self.detector == "builtin":
            fn = _BUILTINS.get(self.builtin)
            if fn is None:
                raise ValueError(f"rule {self.id}: unknown builtin '{self.builtin}'")
            return fn(value)
        raise ValueError(f"rule {self.id}: unknown detector '{self.detector}'")


def _redact(s: str) -> str:
    return s[:6] + "…[REDACTED]" if len(s) > 10 else "[REDACTED]"


def _clip(s: str, n: int = 80) -> str:
    s = s.replace("\n", " ")
    return s if len(s) <= n else s[: n - 1] + "…"


def load_rules(extra_dirs: list[Path] | None = None) -> list[Rule]:
    rules: list[Rule] = []
    sources: list[tuple[str, str]] = []

    pkg_rules = resources.files("blastscope") / "rules"
    for entry in sorted(pkg_rules.iterdir(), key=lambda e: e.name):
        if entry.name.endswith((".yaml", ".yml")):
            sources.append((entry.name, entry.read_text(encoding="utf-8")))

    for d in (extra_dirs or []):
        for p in sorted(Path(d).glob("*.y*ml")):
            sources.append((str(p), p.read_text(encoding="utf-8")))

    seen_ids: set[str] = set()
    for src_name, text in sources:
        doc = yaml.safe_load(text) or {}
        for r in doc.get("rules", []):
            rule = Rule(
                id=r["id"],
                risk_class=r.get("risk_class", "R?"),
                severity=Severity(r.get("severity", "medium")),
                title=r["title"],
                explanation=r.get("explanation", ""),
                remediation=r.get("remediation", ""),
                applies_to=r.get("applies_to", "any_text"),
                detector=r.get("detector", "regex"),
                pattern=r.get("pattern", ""),
                builtin=r.get("builtin", ""),
                mappings=r.get("mappings", {}) or {},
                redact=bool(r.get("redact", False)),
            )
            if rule.id in seen_ids:
                raise ValueError(f"duplicate rule id {rule.id} in {src_name}")
            seen_ids.add(rule.id)
            rule.compile()
            rules.append(rule)
    return rules


def scan_installation(inst: Installation, rules: list[Rule]) -> list[Finding]:
    findings: list[Finding] = []
    for server in inst.servers:
        for rule in rules:
            for location, value in _iter_fields(server, rule.applies_to):
                evidence = rule.check(value)
                if evidence:
                    findings.append(Finding(
                        rule_id=rule.id,
                        risk_class=rule.risk_class,
                        severity=rule.severity,
                        title=rule.title,
                        server=server.name,
                        location=location,
                        evidence=evidence,
                        explanation=rule.explanation,
                        remediation=rule.remediation,
                        mappings=rule.mappings,
                    ))
    findings.sort(key=lambda f: (-f.severity.rank, f.server, f.rule_id))
    return findings
