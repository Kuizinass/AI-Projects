"""Secure Score tools — Microsoft Graph API."""

import logging
from src.auth.identity import get_graph_client

logger = logging.getLogger(__name__)


async def get_secure_score() -> dict:
    """Current Microsoft Secure Score with percentage and trend."""
    client = get_graph_client()
    result = await client.security.secure_scores.get(
        request_configuration=lambda r: setattr(
            r.query_parameters, "top", 1
        )
    )
    if not result or not result.value:
        return {"error": "No secure score data available"}

    score = result.value[0]
    pct = round((score.current_score / score.max_score) * 100, 1) if score.max_score else 0

    return {
        "current_score": score.current_score,
        "max_score": score.max_score,
        "percentage": pct,
        "created_date": str(score.created_date_time),
        "licensed_user_count": score.licensed_user_count,
        "active_user_count": score.active_user_count,
    }


async def list_secure_score_controls() -> list[dict]:
    """All Secure Score controls with current score, max, and remediation guidance."""
    client = get_graph_client()
    result = await client.security.secure_score_control_profiles.get()
    if not result or not result.value:
        return []

    controls = []
    for c in result.value:
        controls.append({
            "id": c.id,
            "title": c.title,
            "current_score": c.current_score,
            "max_score": c.max_score,
            "percentage": round((c.current_score / c.max_score) * 100, 1) if c.max_score else 0,
            "implementation_cost": c.implementation_cost,
            "user_impact": c.user_impact,
            "category": c.control_category,
            "remediation": c.remediation,
            "remediation_impact": c.remediation_impact,
            "action_url": c.action_url,
            "threats": c.threats or [],
        })

    # Sort by largest gap (max - current) descending
    controls.sort(key=lambda x: (x["max_score"] or 0) - (x["current_score"] or 0), reverse=True)
    return controls


async def get_secure_score_history(days: int = 30) -> list[dict]:
    """Secure Score over the last N days (default 30)."""
    client = get_graph_client()
    result = await client.security.secure_scores.get(
        request_configuration=lambda r: setattr(r.query_parameters, "top", days)
    )
    if not result or not result.value:
        return []

    return [
        {
            "date": str(s.created_date_time),
            "score": s.current_score,
            "max_score": s.max_score,
            "percentage": round((s.current_score / s.max_score) * 100, 1) if s.max_score else 0,
        }
        for s in result.value
    ]
