"""v0.1 test suite. Every rule pack must fire on the vulnerable fixture and stay
silent on the clean one — that dual assertion is what stops false-positive drift."""
from pathlib import Path

import pytest

from blastscope.adapters.mcp_static import build_installation, parse_config_file
from blastscope.engine import load_rules, scan_installation
from blastscope.models import Severity
from blastscope.scoring import assess

EXAMPLES = Path(__file__).parent.parent / "examples"


@pytest.fixture(scope="module")
def rules():
    return load_rules()


@pytest.fixture(scope="module")
def vuln_findings(rules):
    inst = build_installation([EXAMPLES / "vulnerable_config.json"], auto_discover=False)
    return scan_installation(inst, rules)


@pytest.fixture(scope="module")
def clean_findings(rules):
    inst = build_installation([EXAMPLES / "clean_config.json"], auto_discover=False)
    return scan_installation(inst, rules)


def test_rule_ids_unique(rules):
    ids = [r.id for r in rules]
    assert len(ids) == len(set(ids))


def test_all_rules_have_mappings(rules):
    # governance-ready output is a core promise: every rule maps to a framework
    for r in rules:
        assert r.mappings, f"{r.id} has no framework mapping"


def test_every_risk_class_fires(vuln_findings):
    classes = {f.risk_class for f in vuln_findings}
    for expected in ("R1", "R4", "R7", "R9", "R10"):
        assert expected in classes, f"no finding for {expected}"


def test_tool_poisoning_detected(vuln_findings):
    assert any(f.rule_id == "BS-R1-002" for f in vuln_findings)


def test_root_filesystem_detected(vuln_findings):
    assert any(f.rule_id == "BS-R4-001" and f.server == "filesystem" for f in vuln_findings)


def test_known_credential_detected(vuln_findings):
    assert any(f.rule_id == "BS-R7-001" for f in vuln_findings)


def test_credentials_are_redacted(vuln_findings):
    # the raw secret must never appear in output
    for f in vuln_findings:
        assert "0123456789" not in f.evidence
        assert "secrettoken" not in f.evidence
        assert "sk-live-9f8e7d6c5b4a3210" not in f.evidence


def test_destructive_tool_detected(vuln_findings):
    assert any(f.rule_id == "BS-R9-001" for f in vuln_findings)


def test_plaintext_http_detected(vuln_findings):
    assert any(f.rule_id == "BS-R10-004" for f in vuln_findings)


def test_vulnerable_config_posture_critical(vuln_findings):
    a = assess(vuln_findings)
    assert a.posture == "CRITICAL"
    assert a.counts["critical"] >= 1
    assert a.total == len(vuln_findings)


def test_clean_config_is_clean(clean_findings):
    a = assess(clean_findings)
    assert a.posture == "CLEAN"
    assert a.highest_severity == "none"
    assert len(clean_findings) == 0


def test_posture_tracks_highest_severity():
    # posture is purely the highest severity present, nothing more
    from blastscope.models import Finding
    high = Finding("X", "R7", Severity.HIGH, "t", "s", "l", "e", "why", "fix")
    med = Finding("Y", "R9", Severity.MEDIUM, "t", "s", "l", "e", "why", "fix")
    assert assess([med, high]).posture == "HIGH RISK"
    assert assess([med]).posture == "MEDIUM RISK"
    crit = Finding("Z", "R1", Severity.CRITICAL, "t", "s", "l", "e", "why", "fix")
    assert assess([med, high, crit]).posture == "CRITICAL"


def test_localhost_http_not_flagged(rules):
    cfg = {"mcpServers": {"local": {"url": "http://localhost:3000/sse"}}}
    p = EXAMPLES / "_tmp_localhost.json"
    import json
    p.write_text(json.dumps(cfg))
    try:
        inst = build_installation([p], auto_discover=False)
        findings = scan_installation(inst, rules)
        assert not any(f.rule_id == "BS-R10-004" for f in findings)
    finally:
        p.unlink()
