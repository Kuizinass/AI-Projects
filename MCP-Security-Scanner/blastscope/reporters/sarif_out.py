"""SARIF 2.1.0 output — drops findings into GitHub code scanning and any
SARIF-aware AppSec pipeline with zero new dashboards."""
from __future__ import annotations

import json

from blastscope import __version__
from blastscope.models import Finding, Installation, Severity
from blastscope.scoring import Assessment

_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

_SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.0",
    Severity.LOW: "2.5",
    Severity.INFO: "0.0",
}


def render(inst: Installation, findings: list[Finding], assessment: Assessment) -> str:
    rules_seen: dict[str, dict] = {}
    results = []

    for f in findings:
        if f.rule_id not in rules_seen:
            rules_seen[f.rule_id] = {
                "id": f.rule_id,
                "name": "".join(w.capitalize() for w in f.title.split()[:6]),
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.explanation.strip() or f.title},
                "help": {"text": f.remediation.strip() or ""},
                "properties": {
                    "security-severity": _SECURITY_SEVERITY[f.severity],
                    "tags": ["security", f.risk_class] +
                            [f"{k}:{v}" for k, v in (f.mappings or {}).items()],
                },
            }
        src = next((s.source_path for s in inst.servers if s.name in f.server and s.source_path), "") \
            or "mcp-configuration"
        results.append({
            "ruleId": f.rule_id,
            "level": _SARIF_LEVEL[f.severity],
            "message": {"text": f"{f.title} — server '{f.server}' at {f.location}. "
                                f"Evidence: {f.evidence}. Fix: {f.remediation.strip()}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": src},
                    "region": {"startLine": 1},
                },
                "logicalLocations": [{"name": f.server, "kind": "resource"}],
            }],
        })

    doc = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "BlastScope",
                "version": __version__,
                "informationUri": "https://github.com/Kuizinass/AI-Projects/tree/main/mcp-security-scanner",
                "rules": list(rules_seen.values()),
            }},
            "results": results,
            "properties": {"posture": assessment.posture, "counts": assessment.counts},
        }],
    }
    return json.dumps(doc, indent=2)
