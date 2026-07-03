"""
MP Cyber Security Advisor — MCP Server
Exposes 28 security tools across the full Microsoft security stack.
"""

import logging
import uuid
from typing import Annotated

from fastmcp import FastMCP
from pydantic import Field

from src.config.settings import settings
from src.risk.engine import ActionContext, score_action

# ── Tool modules ──────────────────────────────────────────────
from src.tools import (
    secure_score,
    defender_xdr,
    defender_cloud,
    sentinel,
    intune,
    purview,
    admin_center,
    escalation,
)
from src.risk.thresholds import RiskLevel

logging.basicConfig(level=settings.log_level)
logger = logging.getLogger(__name__)

mcp = FastMCP(
    name="MP Cyber Security Advisor",
    version="1.0.0",
    description=(
        "Security advisor MCP connected to Defender XDR, Purview, Defender for Cloud, "
        "Sentinel, Intune, and M365 Admin Center. Assesses risk, auto-remediates low-risk "
        "issues, and escalates to analysts via Microsoft Teams."
    ),
)

# ══════════════════════════════════════════════════════════════
# SECURE SCORE
# ══════════════════════════════════════════════════════════════

@mcp.tool()
async def get_secure_score() -> dict:
    """Return the current Microsoft Secure Score with percentage and metadata."""
    return await secure_score.get_secure_score()


@mcp.tool()
async def list_secure_score_controls() -> list[dict]:
    """
    List all Secure Score controls sorted by largest gap (max - current).
    Each control includes remediation steps and action URL.
    """
    return await secure_score.list_secure_score_controls()


@mcp.tool()
async def get_secure_score_history(
    days: Annotated[int, Field(default=30, ge=1, le=90, description="Number of days of history")] = 30
) -> list[dict]:
    """Return Secure Score trend over the last N days."""
    return await secure_score.get_secure_score_history(days)


# ══════════════════════════════════════════════════════════════
# DEFENDER XDR
# ══════════════════════════════════════════════════════════════

@mcp.tool()
async def get_incidents(
    severity: Annotated[str | None, Field(default=None, description="Filter: high | medium | low | informational")] = None,
    limit: Annotated[int, Field(default=50, ge=1, le=200)] = 50,
) -> list[dict]:
    """Get active security incidents from Microsoft Defender XDR."""
    return await defender_xdr.get_incidents(severity=severity, limit=limit)


@mcp.tool()
async def get_alerts(
    severity: Annotated[str | None, Field(default=None, description="Filter: high | medium | low | informational")] = None,
    limit: Annotated[int, Field(default=100, ge=1, le=500)] = 100,
) -> list[dict]:
    """Get security alerts from Microsoft 365 Defender."""
    return await defender_xdr.get_alerts(severity=severity, limit=limit)


@mcp.tool()
async def run_advanced_hunting(
    query: Annotated[str, Field(description="KQL query to run against M365 Defender Advanced Hunting")]
) -> dict:
    """Execute a KQL query against Microsoft 365 Defender Advanced Hunting. Returns schema and rows."""
    return await defender_xdr.run_advanced_hunting(query)


@mcp.tool()
async def get_vulnerabilities(
    device_name: Annotated[str | None, Field(default=None, description="Filter by device DNS name")] = None,
    limit: Annotated[int, Field(default=100, ge=1, le=500)] = 100,
) -> list[dict]:
    """Get CVE vulnerabilities from Defender for Endpoint."""
    return await defender_xdr.get_vulnerabilities(device_name=device_name, limit=limit)


# ══════════════════════════════════════════════════════════════
# DEFENDER FOR CLOUD
# ══════════════════════════════════════════════════════════════

@mcp.tool()
async def get_security_posture() -> dict:
    """Get overall security posture summary from Microsoft Defender for Cloud."""
    return await defender_cloud.get_security_posture()


@mcp.tool()
async def get_recommendations(
    severity: Annotated[str | None, Field(default=None, description="Filter: High | Medium | Low")] = None
) -> list[dict]:
    """Get security recommendations from Defender for Cloud."""
    return await defender_cloud.get_recommendations(severity=severity)


@mcp.tool()
async def get_compliance_status(
    standard: Annotated[str | None, Field(default=None, description="e.g. 'NIST', 'CIS', 'PCI'")] = None
) -> list[dict]:
    """Get regulatory compliance status from Defender for Cloud."""
    return await defender_cloud.get_compliance_status(standard=standard)


@mcp.tool()
async def remediate_recommendation(
    assessment_name: Annotated[str, Field(description="Assessment/recommendation ID")],
    resource_id: Annotated[str, Field(description="Azure resource ID to remediate")],
    description: Annotated[str, Field(description="Human-readable description of the change")],
    affected_count: Annotated[int, Field(default=1, description="Number of assets affected")] = 1,
    total_count: Annotated[int, Field(default=1, description="Total assets in scope")] = 1,
    is_reversible: Annotated[bool, Field(default=True)] = True,
    service_critical: Annotated[bool, Field(default=False)] = False,
    touches_pii: Annotated[bool, Field(default=False)] = False,
    recently_changed: Annotated[bool, Field(default=False)] = False,
    severity: Annotated[str, Field(default="Medium")] = "Medium",
) -> dict:
    """
    Remediate a Defender for Cloud recommendation.
    LOW risk → auto-execute. MEDIUM → Teams approval. HIGH/CRITICAL → escalate only.
    """
    return await defender_cloud.remediate_recommendation(
        assessment_name=assessment_name,
        resource_id=resource_id,
        description=description,
        affected_count=affected_count,
        total_count=total_count,
        is_reversible=is_reversible,
        service_critical=service_critical,
        touches_pii=touches_pii,
        recently_changed=recently_changed,
        severity=severity,
    )


# ══════════════════════════════════════════════════════════════
# MICROSOFT SENTINEL
# ══════════════════════════════════════════════════════════════

@mcp.tool()
async def get_sentinel_incidents(
    severity: Annotated[str | None, Field(default=None, description="High | Medium | Low | Informational")] = None,
    status: Annotated[str | None, Field(default=None, description="New | Active | Closed")] = None,
    limit: Annotated[int, Field(default=50, ge=1, le=200)] = 50,
) -> list[dict]:
    """Get incidents from Microsoft Sentinel."""
    return await sentinel.get_sentinel_incidents(severity=severity, status=status, limit=limit)


@mcp.tool()
async def get_sentinel_alerts(
    limit: Annotated[int, Field(default=100, ge=1, le=500)] = 100
) -> list[dict]:
    """Get security alerts ingested into the Sentinel workspace."""
    return await sentinel.get_sentinel_alerts(limit=limit)


@mcp.tool()
async def run_kql_query(
    query: Annotated[str, Field(description="KQL query to run against the Sentinel Log Analytics workspace")],
    timespan_hours: Annotated[int, Field(default=24, ge=1, le=720)] = 24,
) -> dict:
    """Execute a KQL query against Microsoft Sentinel / Log Analytics."""
    return await sentinel.run_kql_query(query=query, timespan_hours=timespan_hours)


@mcp.tool()
async def get_analytic_rules(
    limit: Annotated[int, Field(default=100, ge=1, le=500)] = 100
) -> list[dict]:
    """Review Sentinel analytic (detection) rules — name, severity, status, MITRE tactics."""
    return await sentinel.get_analytic_rules(limit=limit)


# ══════════════════════════════════════════════════════════════
# MICROSOFT INTUNE
# ══════════════════════════════════════════════════════════════

@mcp.tool()
async def get_device_compliance(
    limit: Annotated[int, Field(default=100, ge=1, le=500)] = 100
) -> list[dict]:
    """Get compliance status for all Intune-managed devices."""
    return await intune.get_device_compliance(limit=limit)


@mcp.tool()
async def get_noncompliant_devices() -> list[dict]:
    """Get all devices currently failing Intune compliance policies."""
    return await intune.get_noncompliant_devices()


@mcp.tool()
async def get_configuration_policies(
    limit: Annotated[int, Field(default=50, ge=1, le=200)] = 50
) -> list[dict]:
    """Review Intune device configuration policies."""
    return await intune.get_configuration_policies(limit=limit)


@mcp.tool()
async def apply_compliance_policy(
    policy_id: Annotated[str, Field(description="Intune compliance policy ID")],
    policy_name: Annotated[str, Field(description="Human-readable policy name")],
    target_group_id: Annotated[str, Field(description="Entra ID group ID to assign the policy to")],
    affected_device_count: Annotated[int, Field(description="Estimated devices affected")] = 1,
    total_device_count: Annotated[int, Field(description="Total managed device count")] = 1,
    is_reversible: Annotated[bool, Field(default=True)] = True,
    service_critical: Annotated[bool, Field(default=False)] = False,
) -> dict:
    """
    Assign an Intune compliance policy to a device group.
    LOW risk → auto-execute. MEDIUM → Teams approval. HIGH/CRITICAL → escalate only.
    """
    return await intune.apply_compliance_policy(
        policy_id=policy_id,
        policy_name=policy_name,
        target_group_id=target_group_id,
        affected_device_count=affected_device_count,
        total_device_count=total_device_count,
        is_reversible=is_reversible,
        service_critical=service_critical,
    )


# ══════════════════════════════════════════════════════════════
# MICROSOFT PURVIEW
# ══════════════════════════════════════════════════════════════

@mcp.tool()
async def get_dlp_alerts(
    limit: Annotated[int, Field(default=50, ge=1, le=200)] = 50
) -> list[dict]:
    """Get Data Loss Prevention policy violation alerts from Microsoft Purview."""
    return await purview.get_dlp_alerts(limit=limit)


@mcp.tool()
async def get_sensitivity_labels() -> list[dict]:
    """Get all sensitivity labels configured in the tenant."""
    return await purview.get_sensitivity_labels()


@mcp.tool()
async def get_data_classifications(
    limit: Annotated[int, Field(default=100, ge=1, le=500)] = 100
) -> dict:
    """Get sensitive information types and data classification findings from Purview."""
    return await purview.get_data_classifications(limit=limit)


# ══════════════════════════════════════════════════════════════
# M365 ADMIN CENTER
# ══════════════════════════════════════════════════════════════

@mcp.tool()
async def get_tenant_security_settings() -> dict:
    """Get tenant-wide security settings including security defaults and domain config."""
    return await admin_center.get_tenant_security_settings()


@mcp.tool()
async def get_mfa_status(
    limit: Annotated[int, Field(default=200, ge=1, le=999)] = 200
) -> dict:
    """
    Get MFA adoption across all users — registered count, percentage, and
    list of admins without MFA registered.
    """
    return await admin_center.get_mfa_status(limit=limit)


@mcp.tool()
async def get_conditional_access_policies(
    limit: Annotated[int, Field(default=50, ge=1, le=200)] = 50
) -> list[dict]:
    """Get all Conditional Access policies with conditions and grant controls."""
    return await admin_center.get_conditional_access_policies(limit=limit)


# ══════════════════════════════════════════════════════════════
# RISK & ESCALATION
# ══════════════════════════════════════════════════════════════

@mcp.tool()
async def assess_risk(
    action_type: Annotated[str, Field(description="Type of action, e.g. 'block_user', 'apply_policy'")],
    description: Annotated[str, Field(description="Full description of the proposed action")],
    affected_resource: Annotated[str, Field(description="Resource name or ID")],
    affected_count: Annotated[int, Field(default=1, description="Number of users/devices affected")] = 1,
    total_count: Annotated[int, Field(default=1, description="Total users/devices in scope")] = 1,
    is_reversible: Annotated[bool, Field(default=True)] = True,
    service_critical: Annotated[bool, Field(default=False)] = False,
    touches_pii: Annotated[bool, Field(default=False)] = False,
    recently_changed: Annotated[bool, Field(default=False)] = False,
    severity: Annotated[str, Field(default="Medium")] = "Medium",
) -> dict:
    """
    Score any proposed action on a 0–100 risk scale with full written reasoning.
    Use this before recommending or executing any change.
    """
    ctx = ActionContext(
        action_type=action_type,
        description=description,
        affected_resource=affected_resource,
        affected_count=affected_count,
        total_count=total_count,
        is_reversible=is_reversible,
        service_critical=service_critical,
        touches_pii=touches_pii,
        recently_changed=recently_changed,
        severity=severity,
    )
    risk = score_action(ctx)
    return {
        "score": risk.score,
        "level": risk.level.value,
        "reasoning": risk.reasoning,
        "factors": risk.factors,
        "auto_execute": risk.level == RiskLevel.LOW,
        "requires_approval": risk.level == RiskLevel.MEDIUM,
        "escalate_only": risk.level in (RiskLevel.HIGH, RiskLevel.CRITICAL),
    }


@mcp.tool()
async def create_action_plan(
    finding_title: Annotated[str, Field(description="Title of the security finding")],
    finding_description: Annotated[str, Field(description="Detailed description of the issue")],
    severity: Annotated[str, Field(description="High | Medium | Low")],
    affected_assets: Annotated[list[str], Field(description="List of affected resource names/IDs")],
    recommended_steps: Annotated[list[str], Field(description="Ordered list of remediation steps")],
    business_impact: Annotated[str, Field(description="Potential business impact if not resolved")],
    deadline_days: Annotated[int, Field(default=30, description="Target remediation deadline in days")] = 30,
) -> dict:
    """
    Generate a structured action plan for a security finding.
    Returns a formatted plan suitable for analyst review or Teams escalation.
    """
    from datetime import datetime, timedelta

    deadline = (datetime.utcnow() + timedelta(days=deadline_days)).strftime("%Y-%m-%d")

    plan = {
        "plan_id": str(uuid.uuid4()),
        "created": datetime.utcnow().isoformat(),
        "title": finding_title,
        "severity": severity,
        "description": finding_description,
        "affected_assets": affected_assets,
        "asset_count": len(affected_assets),
        "business_impact": business_impact,
        "remediation_deadline": deadline,
        "steps": [
            {"step": i + 1, "action": step}
            for i, step in enumerate(recommended_steps)
        ],
        "formatted_summary": (
            f"**{severity.upper()} — {finding_title}**\n\n"
            f"{finding_description}\n\n"
            f"**Affected assets ({len(affected_assets)}):** {', '.join(affected_assets[:5])}"
            + (" + more..." if len(affected_assets) > 5 else "") + "\n\n"
            f"**Business impact:** {business_impact}\n\n"
            f"**Remediation steps:**\n"
            + "\n".join(f"{i+1}. {s}" for i, s in enumerate(recommended_steps))
            + f"\n\n**Target deadline:** {deadline}"
        ),
    }
    return plan


@mcp.tool()
async def escalate_to_analyst(
    action_id: Annotated[str, Field(description="Unique action/finding ID")],
    action_description: Annotated[str, Field(description="What needs analyst attention")],
    affected_resource: Annotated[str, Field(description="Affected resource name or ID")],
    risk_score: Annotated[int, Field(ge=0, le=100, description="Risk score 0–100")],
    risk_reasoning: Annotated[str, Field(description="Explanation of the risk assessment")],
    portal_url: Annotated[str, Field(default="", description="Deep link to the relevant portal")] = "",
    action_plan: Annotated[str, Field(default="", description="Optional formatted action plan text")] = "",
    require_approval: Annotated[bool, Field(default=False, description="True if analyst must approve/reject")] = False,
) -> dict:
    """
    Send an escalation card to the security analyst Teams channel.
    Use for findings that require human attention or decisions above risk threshold.
    """
    from src.risk.thresholds import RiskScore, classify

    risk = RiskScore(
        score=risk_score,
        level=classify(risk_score),
        reasoning=risk_reasoning,
        factors={},
    )

    return await escalation.send_escalation_card(
        action_id=action_id,
        action_description=action_description,
        affected_resource=affected_resource,
        risk=risk,
        portal_url=portal_url,
        action_plan=action_plan,
        require_approval=require_approval,
    )


# ══════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "src.server:mcp",
        host="0.0.0.0",
        port=settings.mcp_server_port,
        log_level=settings.log_level.lower(),
    )
