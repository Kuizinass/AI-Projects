"""Tests for the risk scoring engine — no Azure credentials required."""

import pytest
from src.risk.engine import ActionContext, score_action
from src.risk.thresholds import RiskLevel


def _ctx(**kwargs) -> ActionContext:
    defaults = dict(
        action_type="test_action",
        description="Test action",
        affected_resource="resource/test",
        affected_count=1,
        total_count=100,
        is_reversible=True,
        service_critical=False,
        touches_pii=False,
        recently_changed=False,
        severity="Low",
    )
    defaults.update(kwargs)
    return ActionContext(**defaults)


class TestRiskClassification:
    def test_low_risk_reversible_small_scope(self):
        ctx = _ctx(affected_count=1, total_count=100, is_reversible=True)
        result = score_action(ctx)
        assert result.level == RiskLevel.LOW
        assert result.score <= 30

    def test_medium_risk_irreversible(self):
        ctx = _ctx(
            affected_count=10,
            total_count=100,
            is_reversible=False,
            severity="Medium",
        )
        result = score_action(ctx)
        assert result.level in (RiskLevel.MEDIUM, RiskLevel.HIGH)

    def test_high_risk_large_scope_pii_critical(self):
        ctx = _ctx(
            affected_count=95,
            total_count=100,
            is_reversible=False,
            service_critical=True,
            touches_pii=True,
            recently_changed=True,
            severity="High",
        )
        result = score_action(ctx)
        assert result.level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
        assert result.score > 70

    def test_critical_all_factors_maxed(self):
        ctx = _ctx(
            affected_count=100,
            total_count=100,
            is_reversible=False,
            service_critical=True,
            touches_pii=True,
            recently_changed=True,
            severity="Critical",
        )
        result = score_action(ctx)
        assert result.score == 100
        assert result.level == RiskLevel.CRITICAL

    def test_score_capped_at_100(self):
        ctx = _ctx(
            affected_count=100,
            total_count=100,
            is_reversible=False,
            service_critical=True,
            touches_pii=True,
            recently_changed=True,
            severity="Critical",
        )
        result = score_action(ctx)
        assert result.score <= 100

    def test_reasoning_includes_description(self):
        ctx = _ctx(description="Enable MFA enforcement for all users")
        result = score_action(ctx)
        assert "Enable MFA enforcement" in result.reasoning

    def test_reasoning_includes_score(self):
        ctx = _ctx()
        result = score_action(ctx)
        assert str(result.score) in result.reasoning

    def test_factors_sum_matches_score(self):
        ctx = _ctx(
            affected_count=10,
            total_count=100,
            is_reversible=True,
            service_critical=False,
            touches_pii=False,
            recently_changed=False,
            severity="Low",
        )
        result = score_action(ctx)
        # Score should equal sum of factors (no severity bonus for Low)
        assert result.score == sum(result.factors.values())

    def test_auto_execute_decision_low(self):
        ctx = _ctx(affected_count=1, total_count=1000)
        result = score_action(ctx)
        assert result.level == RiskLevel.LOW
        assert "auto" in result.reasoning.lower() or "automatically" in result.reasoning.lower()

    def test_escalate_decision_high(self):
        ctx = _ctx(
            affected_count=80,
            total_count=100,
            is_reversible=False,
            service_critical=True,
            severity="High",
        )
        result = score_action(ctx)
        if result.level in (RiskLevel.HIGH, RiskLevel.CRITICAL):
            assert "escalat" in result.reasoning.lower()

    def test_zero_total_count_handled(self):
        """Should not raise ZeroDivisionError when total_count is 0."""
        ctx = _ctx(affected_count=0, total_count=0)
        result = score_action(ctx)
        assert result.score >= 0


class TestRiskFactors:
    def test_pii_adds_score(self):
        base = score_action(_ctx(touches_pii=False))
        with_pii = score_action(_ctx(touches_pii=True))
        assert with_pii.score > base.score

    def test_irreversible_adds_score(self):
        reversible = score_action(_ctx(is_reversible=True))
        irreversible = score_action(_ctx(is_reversible=False))
        assert irreversible.score > reversible.score

    def test_service_critical_adds_score(self):
        normal = score_action(_ctx(service_critical=False))
        critical = score_action(_ctx(service_critical=True))
        assert critical.score > normal.score

    def test_recently_changed_adds_score(self):
        stable = score_action(_ctx(recently_changed=False))
        changed = score_action(_ctx(recently_changed=True))
        assert changed.score > stable.score

    def test_large_scope_adds_score(self):
        small = score_action(_ctx(affected_count=1, total_count=100))
        large = score_action(_ctx(affected_count=99, total_count=100))
        assert large.score > small.score
