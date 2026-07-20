"""Composition engine — R3 (lethal trifecta) and R12 (excessive agency).

This is what sets BlastScope apart. Per-server rules assess each server alone.
This module assesses the INSTALLATION: what the union of all installed tools can
do if a single component is compromised by prompt injection.

R3 — Lethal trifecta:
    An installation is critically exposed when the same agent can reach, in any
    combination across servers:
        PRIVATE_DATA  +  UNTRUSTED_IN  +  EXFIL
    Untrusted input carries the injection, private data is the prize, exfil is the
    way out. No single server has to be malicious for this to be game over.

R12 — Excessive agency:
    Aggregate blast radius of the whole installed set, independent of the trifecta.
    A pair of (UNTRUSTED_IN + DESTRUCTIVE) is its own high-severity chain: injected
    content that can trigger irreversible action. We also surface total reach.
"""
from __future__ import annotations

from itertools import combinations

from blastscope.capabilities import (
    Capability,
    ServerCapabilities,
    classify_installation,
)
from blastscope.models import Finding, Installation, Severity


def _servers_with(caps_list: list[ServerCapabilities], cap: Capability) -> list[str]:
    return [c.server for c in caps_list if cap in c.capabilities]


def _evidence_for(caps_list: list[ServerCapabilities], cap: Capability) -> str:
    bits = []
    for c in caps_list:
        for e in c.evidence:
            if e.capability == cap:
                bits.append(f"{c.server}.{e.tool} ('{e.signal}')")
                break
    return "; ".join(bits)


def analyse_composition(inst: Installation) -> list[Finding]:
    caps_list = classify_installation(inst.servers)
    findings: list[Finding] = []

    have_private = _servers_with(caps_list, Capability.PRIVATE_DATA)
    have_untrusted = _servers_with(caps_list, Capability.UNTRUSTED_IN)
    have_exfil = _servers_with(caps_list, Capability.EXFIL)
    have_destructive = _servers_with(caps_list, Capability.DESTRUCTIVE)

    # ---- R3: lethal trifecta -------------------------------------------------
    if have_private and have_untrusted and have_exfil:
        involved = sorted(set(have_private + have_untrusted + have_exfil))
        findings.append(Finding(
            rule_id="BS-R3-001",
            risk_class="R3",
            severity=Severity.CRITICAL,
            title="Lethal trifecta present across installation",
            server=", ".join(involved),
            location="installation-wide",
            evidence=(
                f"private data: {_evidence_for(caps_list, Capability.PRIVATE_DATA)} | "
                f"untrusted input: {_evidence_for(caps_list, Capability.UNTRUSTED_IN)} | "
                f"exfil: {_evidence_for(caps_list, Capability.EXFIL)}"
            ),
            explanation=(
                "This installation can (1) read private data, (2) ingest attacker-"
                "influenceable content, and (3) send data to an external destination. "
                "A single prompt injection in any fetched web page, email, or issue can "
                "chain these into data theft — no individual server has to be malicious. "
                "This is the highest-impact pattern in agentic AI and per-server scanners "
                "cannot see it."
            ),
            remediation=(
                "Break the chain: isolate the untrusted-input server into a separate "
                "client profile with no data/exfil tools, OR constrain the exfil tool "
                "with a URL allow-list, OR remove one leg entirely. You only need to "
                "sever one link."
            ),
            mappings={"owasp_llm10": "LLM01 Prompt Injection + LLM02 + LLM06",
                      "mitre_atlas": "AML.T0051 → AML.T0057",
                      "nist_ai_rmf": "MANAGE"},
        ))

    # ---- R12a: injection-to-destruction chain -------------------------------
    if have_untrusted and have_destructive:
        involved = sorted(set(have_untrusted + have_destructive))
        findings.append(Finding(
            rule_id="BS-R12-001",
            risk_class="R12",
            severity=Severity.HIGH,
            title="Untrusted input can reach destructive action",
            server=", ".join(involved),
            location="installation-wide",
            evidence=(
                f"untrusted input: {_evidence_for(caps_list, Capability.UNTRUSTED_IN)} | "
                f"destructive: {_evidence_for(caps_list, Capability.DESTRUCTIVE)}"
            ),
            explanation=(
                "The agent can ingest attacker-influenceable content AND perform "
                "irreversible actions (delete, deploy, pay, execute). Injected content "
                "can drive destructive operations without the trifecta's exfil leg."
            ),
            remediation=(
                "Require human-in-the-loop confirmation on destructive tools, or keep "
                "them out of any agent that also touches untrusted content."
            ),
            mappings={"owasp_llm10": "LLM06 Excessive Agency",
                      "mitre_atlas": "AML.T0051 → AML.T0055",
                      "nist_ai_rmf": "MANAGE"},
        ))

    # ---- R12b: aggregate blast-radius summary -------------------------------
    present = [c for c in (Capability.PRIVATE_DATA, Capability.UNTRUSTED_IN,
                           Capability.EXFIL, Capability.DESTRUCTIVE)
               if _servers_with(caps_list, c)]
    if len(present) >= 2:
        # informational-to-medium: describe total reach so a reviewer sees the surface
        sev = Severity.MEDIUM if len(present) >= 3 else Severity.LOW
        # don't double-report if trifecta already fired at critical — keep as context
        reach = ", ".join(c.value.replace("_", " ") for c in present)
        findings.append(Finding(
            rule_id="BS-R12-002",
            risk_class="R12",
            severity=sev,
            title=f"Aggregate agent reach spans {len(present)} capability classes",
            server=f"{len(inst.servers)} servers",
            location="installation-wide",
            evidence=f"capabilities present: {reach}",
            explanation=(
                "Blast-radius summary: if the model driving this installation is "
                "compromised, these are the capability classes it can exercise. More "
                "classes in one agent means a larger single point of failure."
            ),
            remediation=(
                "Apply least privilege across the installation. Split high-capability "
                "servers across separate client profiles so no single agent holds the "
                "full set."
            ),
            mappings={"owasp_llm10": "LLM06 Excessive Agency",
                      "nist_ai_rmf": "GOVERN"},
        ))

    return findings
