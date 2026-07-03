"""
Risk scoring engine. Every write action passes through here before execution.

Score 0–100:
  0–30   LOW      → auto-execute
  31–70  MEDIUM   → Teams approval card, await response
  71–90  HIGH     → escalate only, never execute
  91–100 CRITICAL → immediate escalation
"""

from dataclasses import dataclass
from src.risk.thresholds import RiskScore, RiskLevel, classify, RISK_FACTOR_WEIGHTS


@dataclass
class ActionContext:
    action_type: str          # e.g. "remediate_recommendation", "apply_policy"
    description: str          # human-readable description of the change
    affected_resource: str    # resource ID or name
    affected_count: int       # number of users/devices impacted
    total_count: int          # total users/devices in scope
    is_reversible: bool       # can the change be undone?
    service_critical: bool    # is the resource business-critical?
    touches_pii: bool         # does the action involve personal data?
    recently_changed: bool    # was this resource changed in the last 7 days?
    severity: str             # original severity from the platform (High/Medium/Low)


def score_action(ctx: ActionContext) -> RiskScore:
    factors: dict[str, int] = {}

    # Affected scope (proportion of total)
    if ctx.total_count > 0:
        proportion = ctx.affected_count / ctx.total_count
    else:
        proportion = 1.0
    factors["affected_users"] = int(proportion * RISK_FACTOR_WEIGHTS["affected_users"])

    # Reversibility
    factors["reversibility"] = 0 if ctx.is_reversible else RISK_FACTOR_WEIGHTS["reversibility"]

    # Service impact
    factors["service_impact"] = (
        RISK_FACTOR_WEIGHTS["service_impact"] if ctx.service_critical else
        int(RISK_FACTOR_WEIGHTS["service_impact"] * 0.3)
    )

    # Data sensitivity
    factors["data_sensitivity"] = (
        RISK_FACTOR_WEIGHTS["data_sensitivity"] if ctx.touches_pii else 0
    )

    # Change frequency bonus
    factors["change_frequency"] = (
        RISK_FACTOR_WEIGHTS["change_frequency"] if ctx.recently_changed else 0
    )

    # Severity uplift — platform-rated HIGH/CRITICAL adds 10 pts
    severity_bonus = 10 if ctx.severity.lower() in ("high", "critical") else 0

    total = sum(factors.values()) + severity_bonus
    total = min(total, 100)
    level = classify(total)

    reasoning = _build_reasoning(ctx, factors, severity_bonus, total, level)

    return RiskScore(score=total, level=level, reasoning=reasoning, factors=factors)


def _build_reasoning(
    ctx: ActionContext,
    factors: dict[str, int],
    severity_bonus: int,
    total: int,
    level: RiskLevel,
) -> str:
    lines = [
        f"Risk assessment for: {ctx.description}",
        f"Overall risk score: {total}/100 → {level.value}",
        "",
        "Factor breakdown:",
        f"  • Affected scope:      {factors['affected_users']}/20 "
        f"({ctx.affected_count}/{ctx.total_count} assets)",
        f"  • Reversibility:       {factors['reversibility']}/25 "
        f"({'irreversible' if not ctx.is_reversible else 'reversible'})",
        f"  • Service impact:      {factors['service_impact']}/20 "
        f"({'service-critical resource' if ctx.service_critical else 'non-critical'})",
        f"  • Data sensitivity:    {factors['data_sensitivity']}/20 "
        f"({'touches PII/PHI' if ctx.touches_pii else 'no sensitive data'})",
        f"  • Change frequency:    {factors['change_frequency']}/15 "
        f"({'recently modified' if ctx.recently_changed else 'stable'})",
        f"  • Severity uplift:     {severity_bonus} "
        f"(platform severity: {ctx.severity})",
        "",
        f"Decision: ",
    ]
    if level == RiskLevel.LOW:
        lines.append("Action will be executed automatically — risk is within acceptable threshold.")
    elif level == RiskLevel.MEDIUM:
        lines.append(
            "Risk exceeds auto-execute threshold. Sending approval request to security analyst via Teams."
        )
    else:
        lines.append(
            f"Risk is {level.value}. Action will NOT be executed. "
            "Escalating to security analyst with full context and recommended action plan."
        )

    return "\n".join(lines)
