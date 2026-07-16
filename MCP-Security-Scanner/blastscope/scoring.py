"""Installation-level assessment.

No letter grades. Security findings speak for themselves: what was found, at what
severity, and what the worst-case exposure is. The posture label is derived
strictly from the highest-severity finding present — it is a summary of the
findings, not a score layered on top of them.
"""
from __future__ import annotations

from dataclasses import dataclass

from blastscope.models import Finding, Severity

# Posture is the highest severity present. Purely descriptive.
POSTURE_BY_SEVERITY = {
    Severity.CRITICAL: "CRITICAL",
    Severity.HIGH: "HIGH RISK",
    Severity.MEDIUM: "MEDIUM RISK",
    Severity.LOW: "LOW RISK",
}


@dataclass
class Assessment:
    posture: str              # CRITICAL | HIGH RISK | MEDIUM RISK | LOW RISK | CLEAN
    highest_severity: str     # critical | high | medium | low | none
    verdict: str
    counts: dict[str, int]
    total: int


def _verdict(findings: list[Finding]) -> str:
    if not findings:
        return ("No known risk patterns detected. This means 'nothing found', "
                "not 'safe' — review the threat model for what v0.1 cannot see.")
    worst = findings[0]
    high_impact = [f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
    if worst.severity == Severity.CRITICAL:
        return (f"Critical exposure via '{worst.server}' ({worst.title.lower()}). "
                f"Treat this installation as compromised-by-default until remediated.")
    if high_impact:
        return (f"{len(high_impact)} high-impact finding(s), led by '{worst.server}': "
                f"{worst.title.lower()}. Remediate before trusting this installation "
                f"with sensitive data.")
    return ("Hygiene issues only — no critical or high findings, but hygiene is how "
            "real incidents start. Clear them before they compound.")


def assess(findings: list[Finding]) -> Assessment:
    counts = {s.value: 0 for s in Severity}
    for f in findings:
        counts[f.severity.value] += 1

    if not findings:
        return Assessment(posture="CLEAN", highest_severity="none",
                          verdict=_verdict(findings), counts=counts, total=0)

    highest = sorted(findings, key=lambda f: f.severity.rank, reverse=True)[0].severity
    return Assessment(
        posture=POSTURE_BY_SEVERITY[highest],
        highest_severity=highest.value,
        verdict=_verdict(findings),
        counts=counts,
        total=len(findings),
    )
