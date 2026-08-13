"""Policy engine — organisational baselines for MCP installations.

Per-server rules and composition analysis answer "what is risky?". Policy answers
"what does OUR organisation allow?". A policy file expresses rules that generic
scanning cannot know: which servers are approved, which capability combinations
are banned, what hygiene is mandatory.

Policy file format (YAML):

    # corp-baseline.yaml
    version: 1
    allow_servers:                 # if present, anything not matching is a violation
      - "@modelcontextprotocol/*"
      - "@internal/*"
    deny_servers:                  # always-banned patterns (checked even without allow list)
      - "*paste*"
    deny_capability_combinations:  # capability sets that must not co-exist in one installation
      - [private_data, exfiltration]
      - [untrusted_input, destructive]
    require:
      version_pinning: true        # npx/uvx packages must pin an exact version
      no_plaintext_secrets: true   # any R7 finding becomes a policy violation too
      https_only: true             # remote servers must use https
    max_severity: high             # any finding above this is a policy violation

Matching uses fnmatch-style globs against server name, command and args.
"""
from __future__ import annotations

import fnmatch
import re
from pathlib import Path

import yaml

from blastscope.capabilities import Capability, classify_installation
from blastscope.models import Finding, Installation, ServerConfig, Severity


class PolicyError(ValueError):
    pass


def load_policy(path: Path) -> dict:
    doc = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    if not isinstance(doc, dict):
        raise PolicyError("policy file must be a YAML mapping")
    for combo in doc.get("deny_capability_combinations", []) or []:
        for cap in combo:
            if cap not in {c.value for c in Capability}:
                raise PolicyError(
                    f"unknown capability '{cap}' in deny_capability_combinations; "
                    f"valid: {sorted(c.value for c in Capability)}")
    return doc


def _identity_strings(server: ServerConfig) -> list[str]:
    return [server.name, server.command, server.url, *server.args]


def _matches_any(server: ServerConfig, patterns: list[str]) -> bool:
    for ident in _identity_strings(server):
        if not ident:
            continue
        for pat in patterns:
            if fnmatch.fnmatch(ident.lower(), pat.lower()):
                return True
    return False


_PIN_RE = re.compile(r"@\d[\w.-]*$")


def _is_pinned(server: ServerConfig) -> bool:
    """For npx/uvx-launched servers: at least one arg must carry an exact version."""
    if server.command not in ("npx", "uvx", "pnpx", "bunx"):
        return True  # pinning requirement only applies to runner-launched packages
    pkg_args = [a for a in server.args if not a.startswith("-") and "/" not in a.strip("@")
                or a.startswith("@")]
    candidates = [a for a in server.args if not a.startswith("-")]
    if not candidates:
        return True
    return any(_PIN_RE.search(a) for a in candidates)


def evaluate_policy(inst: Installation, policy: dict,
                    scan_findings: list[Finding] | None = None) -> list[Finding]:
    """Return policy-violation findings for this installation."""
    violations: list[Finding] = []

    def add(rule_id, severity, title, server, evidence, explanation, remediation):
        violations.append(Finding(
            rule_id=rule_id, risk_class="POLICY", severity=severity, title=title,
            server=server, location="policy", evidence=evidence,
            explanation=explanation, remediation=remediation,
            mappings={"nist_ai_rmf": "GOVERN"},
        ))

    allow = policy.get("allow_servers") or []
    deny = policy.get("deny_servers") or []
    require = policy.get("require") or {}

    for server in inst.servers:
        if deny and _matches_any(server, deny):
            add("BS-POL-001", Severity.HIGH, "Server matches organisational deny list",
                server.name, f"matched deny pattern in policy",
                "This server is explicitly banned by organisational policy.",
                "Remove the server, or update the policy if the ban is obsolete.")
        elif allow and not _matches_any(server, allow):
            add("BS-POL-002", Severity.HIGH, "Server not on organisational allow list",
                server.name, "no allow_servers pattern matched",
                "Only approved servers may be installed under this policy. "
                "Unapproved servers are unreviewed supply chain.",
                "Request approval and add the server to allow_servers, or remove it.")

        if require.get("version_pinning") and not _is_pinned(server):
            add("BS-POL-003", Severity.MEDIUM, "Package not version-pinned (policy requires pinning)",
                server.name, " ".join([server.command] + server.args),
                "Policy requires exact version pins on runner-launched packages so the "
                "code that runs tomorrow is the code that was reviewed.",
                "Pin to an exact version, e.g. package@1.4.2.")

        if require.get("https_only") and server.url.startswith("http://") \
                and not re.match(r"^http://(localhost|127\.0\.0\.1|\[::1\])", server.url):
            add("BS-POL-004", Severity.HIGH, "Remote server violates https-only policy",
                server.name, server.url,
                "Policy requires TLS on all remote MCP transports.",
                "Move the server behind https.")

    # capability-combination bans operate installation-wide
    combos = policy.get("deny_capability_combinations") or []
    if combos:
        caps_list = classify_installation(inst.servers)
        installed_caps = {c for sc in caps_list for c in sc.capabilities}
        for combo in combos:
            wanted = {Capability(c) for c in combo}
            if wanted.issubset(installed_caps):
                holders = sorted({sc.server for sc in caps_list
                                  if sc.capabilities & wanted})
                add("BS-POL-005", Severity.CRITICAL,
                    f"Banned capability combination present: {' + '.join(sorted(combo))}",
                    ", ".join(holders),
                    f"capabilities {sorted(combo)} co-exist across installed servers",
                    "Organisational policy forbids this capability combination in a "
                    "single installation because it forms an attack chain.",
                    "Split the involved servers across separate client profiles or "
                    "remove one of the capabilities.")

    if require.get("no_plaintext_secrets") and scan_findings:
        for f in scan_findings:
            if f.risk_class == "R7":
                add("BS-POL-006", Severity.HIGH,
                    "Plaintext secret violates organisational policy",
                    f.server, f"{f.rule_id} at {f.location}",
                    "Policy requires all credentials in keychain or env references.",
                    "Rotate the credential and move it out of the config file.")
                break  # one policy violation summarising the class is enough

    max_sev = policy.get("max_severity")
    if max_sev and scan_findings:
        threshold = Severity(max_sev).rank
        over = [f for f in scan_findings if f.severity.rank > threshold]
        if over:
            add("BS-POL-007", Severity.HIGH,
                f"Findings exceed policy severity ceiling ({max_sev})",
                f"{len(over)} finding(s)",
                "; ".join(f"{f.rule_id}:{f.server}" for f in over[:5]),
                "Policy caps acceptable residual risk at "
                f"'{max_sev}'. Anything above it must be remediated, not accepted.",
                "Remediate the listed findings or obtain a documented exception.")

    return violations
