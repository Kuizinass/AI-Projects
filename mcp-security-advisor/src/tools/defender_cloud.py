"""
Defender for Cloud (Azure Security Center) tools.
Uses azure-mgmt-security SDK authenticated via Managed Identity.
"""

import logging
import uuid
import httpx
from azure.mgmt.security.aio import SecurityCenter
from src.auth.identity import get_credential, get_azure_token
from src.config.settings import settings
from src.risk.engine import ActionContext, score_action
from src.risk.thresholds import RiskLevel
from src.tools.escalation import send_escalation_card

logger = logging.getLogger(__name__)


def _security_client() -> SecurityCenter:
    return SecurityCenter(
        credential=get_credential(),
        subscription_id=settings.azure_subscription_id,
    )


async def get_security_posture() -> dict:
    """High-level security posture summary from Defender for Cloud."""
    client = _security_client()
    async with client:
        scores = []
        async for score in client.secure_scores.list():
            scores.append({
                "name": score.name,
                "display_name": score.display_name,
                "current_score": score.score.current if score.score else None,
                "max_score": score.score.max if score.score else None,
                "percentage": score.score.percentage if score.score else None,
                "weight": score.weight,
            })
    return {"secure_scores": scores}


async def get_recommendations(severity: str | None = None) -> list[dict]:
    """
    Security recommendations from Defender for Cloud.
    severity: 'High', 'Medium', 'Low' (optional filter)
    """
    client = _security_client()
    results = []
    async with client:
        async for task in client.tasks.list():
            sev = task.state
            rec = {
                "id": task.id,
                "name": task.name,
                "recommendation_name": task.recommendation_name,
                "recommendation_type": task.recommendation_type,
                "state": task.state,
                "start_time": str(task.start_time) if task.start_time else None,
                "creation_time": str(task.creation_time) if task.creation_time else None,
            }
            results.append(rec)

    return results


async def get_compliance_status(standard: str | None = None) -> list[dict]:
    """
    Regulatory compliance status (NIST 800-53, CIS, PCI DSS, etc.)
    Optionally filter by standard name.
    """
    client = _security_client()
    results = []
    async with client:
        async for assessment in client.regulatory_compliance_standards.list():
            if standard and standard.lower() not in (assessment.name or "").lower():
                continue
            results.append({
                "name": assessment.name,
                "state": assessment.state,
                "passed_controls": assessment.passed_controls,
                "failed_controls": assessment.failed_controls,
                "skipped_controls": assessment.skipped_controls,
                "unsupported_controls": assessment.unsupported_controls,
            })
    return results


async def remediate_recommendation(
    assessment_name: str,
    resource_id: str,
    description: str,
    affected_count: int = 1,
    total_count: int = 1,
    is_reversible: bool = True,
    service_critical: bool = False,
    touches_pii: bool = False,
    recently_changed: bool = False,
    severity: str = "Medium",
) -> dict:
    """
    Attempt to remediate a Defender for Cloud recommendation.
    Passes through the risk gate before any action is taken.
    """
    action_id = str(uuid.uuid4())

    ctx = ActionContext(
        action_type="remediate_recommendation",
        description=description,
        affected_resource=resource_id,
        affected_count=affected_count,
        total_count=total_count,
        is_reversible=is_reversible,
        service_critical=service_critical,
        touches_pii=touches_pii,
        recently_changed=recently_changed,
        severity=severity,
    )

    risk = score_action(ctx)
    portal_url = (
        f"https://portal.azure.com/#blade/Microsoft_Azure_Security/RecommendationsBlade"
    )

    if risk.level == RiskLevel.LOW:
        logger.info("Auto-remediating [%s] risk=%s", assessment_name, risk.score)
        # Trigger the built-in remediation via REST
        token = await get_azure_token("https://management.azure.com/.default")
        url = (
            f"https://management.azure.com{resource_id}"
            f"/providers/Microsoft.Security/assessments/{assessment_name}/remediations"
            f"?api-version=2021-06-01"
        )
        async with httpx.AsyncClient(timeout=30) as http:
            resp = await http.post(url, headers={"Authorization": f"Bearer {token}"})

        return {
            "action_id": action_id,
            "outcome": "executed",
            "risk_level": risk.level.value,
            "risk_score": risk.score,
            "reasoning": risk.reasoning,
            "http_status": resp.status_code,
        }

    elif risk.level == RiskLevel.MEDIUM:
        await send_escalation_card(
            action_id=action_id,
            action_description=description,
            affected_resource=resource_id,
            risk=risk,
            portal_url=portal_url,
            require_approval=True,
        )
        return {
            "action_id": action_id,
            "outcome": "pending_approval",
            "risk_level": risk.level.value,
            "risk_score": risk.score,
            "reasoning": risk.reasoning,
            "message": "Approval request sent to security analyst via Teams.",
        }

    else:
        await send_escalation_card(
            action_id=action_id,
            action_description=description,
            affected_resource=resource_id,
            risk=risk,
            portal_url=portal_url,
            require_approval=False,
        )
        return {
            "action_id": action_id,
            "outcome": "escalated",
            "risk_level": risk.level.value,
            "risk_score": risk.score,
            "reasoning": risk.reasoning,
            "message": f"Risk is {risk.level.value}. Action blocked. Analyst notified via Teams.",
        }
