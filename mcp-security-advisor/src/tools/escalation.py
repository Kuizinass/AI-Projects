"""
Microsoft Teams escalation via Incoming Webhook.
Posts an Adaptive Card with Approve / Reject actions.
"""

import httpx
import logging
from src.config.settings import settings
from src.risk.thresholds import RiskScore, RiskLevel

logger = logging.getLogger(__name__)

_LEVEL_COLOURS = {
    RiskLevel.LOW:      "good",      # green
    RiskLevel.MEDIUM:   "warning",   # amber
    RiskLevel.HIGH:     "attention", # red
    RiskLevel.CRITICAL: "attention",
}


async def send_escalation_card(
    action_id: str,
    action_description: str,
    affected_resource: str,
    risk: RiskScore,
    portal_url: str = "",
    action_plan: str = "",
    require_approval: bool = False,
) -> dict:
    """
    Post an Adaptive Card to the Teams security channel.

    require_approval=True  → card shows Approve / Reject buttons (MEDIUM risk)
    require_approval=False → informational card only (HIGH / CRITICAL)
    """
    colour = _LEVEL_COLOURS.get(risk.level, "attention")

    body = [
        {
            "type": "TextBlock",
            "size": "Large",
            "weight": "Bolder",
            "text": f"🔒 Security Action {'Requires Approval' if require_approval else 'Escalation'}",
        },
        {
            "type": "FactSet",
            "facts": [
                {"title": "Action", "value": action_description},
                {"title": "Resource", "value": affected_resource},
                {"title": "Risk Level", "value": f"{risk.level.value} ({risk.score}/100)"},
            ],
        },
        {
            "type": "TextBlock",
            "text": "**Risk Reasoning**",
            "weight": "Bolder",
            "wrap": True,
        },
        {
            "type": "TextBlock",
            "text": risk.reasoning.replace("\n", "\n\n"),
            "wrap": True,
        },
    ]

    if action_plan:
        body += [
            {"type": "TextBlock", "text": "**Recommended Action Plan**", "weight": "Bolder", "wrap": True},
            {"type": "TextBlock", "text": action_plan, "wrap": True},
        ]

    actions = []
    if require_approval and settings.teams_callback_base_url:
        callback_approve = f"{settings.teams_callback_base_url}/api/approval/{action_id}/approve"
        callback_reject = f"{settings.teams_callback_base_url}/api/approval/{action_id}/reject"
        actions = [
            {"type": "Action.OpenUrl", "title": "✅ Approve", "url": callback_approve},
            {"type": "Action.OpenUrl", "title": "❌ Reject", "url": callback_reject},
        ]

    if portal_url:
        actions.append({"type": "Action.OpenUrl", "title": "Open in Portal", "url": portal_url})

    card_payload = {
        "type": "message",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.4",
                    "msteams": {"width": "Full"},
                    "body": body,
                    "actions": actions,
                },
            }
        ],
    }

    async with httpx.AsyncClient(timeout=15) as client:
        response = await client.post(
            settings.teams_webhook_url,
            json=card_payload,
            headers={"Content-Type": "application/json"},
        )

    if response.status_code not in (200, 202):
        logger.error("Teams webhook failed: %s %s", response.status_code, response.text)
        return {"sent": False, "error": response.text}

    logger.info(
        "Teams card sent | action_id=%s risk=%s/%s",
        action_id, risk.level.value, risk.score,
    )
    return {"sent": True, "action_id": action_id, "risk_level": risk.level.value}
