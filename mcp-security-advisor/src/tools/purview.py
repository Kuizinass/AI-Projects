"""Microsoft Purview tools — Graph API (Information Protection + Compliance)."""

import logging
from src.auth.identity import get_graph_client

logger = logging.getLogger(__name__)


async def get_dlp_alerts(limit: int = 50) -> list[dict]:
    """Data Loss Prevention policy violations from Microsoft Purview."""
    client = get_graph_client()

    # DLP alerts are surfaced via the security alerts API with category filter
    result = await client.security.alerts_v2.get(
        request_configuration=lambda r: setattr(
            r.query_parameters, "filter", "category eq 'DataLossPrevention'"
        )
    )
    if not result or not result.value:
        return []

    return [
        {
            "id": a.id,
            "title": a.title,
            "severity": a.severity.value if a.severity else None,
            "status": a.status.value if a.status else None,
            "category": a.category,
            "created": str(a.created_date_time) if a.created_date_time else None,
            "description": a.description,
            "recommended_actions": a.recommended_actions,
            "service_source": a.service_source.value if a.service_source else None,
        }
        for a in result.value[:limit]
    ]


async def get_sensitivity_labels() -> list[dict]:
    """Sensitivity labels configured in the tenant."""
    client = get_graph_client()
    result = await client.security.information_protection.sensitivity_labels.get()
    if not result or not result.value:
        return []

    return [
        {
            "id": lbl.id,
            "name": lbl.name,
            "display_name": lbl.display_name,
            "description": lbl.description,
            "color": lbl.color,
            "sensitivity": lbl.sensitivity,
            "tooltip": lbl.tooltip,
            "is_active": lbl.is_active,
            "is_appliable_to_email": lbl.applicable_to.value if lbl.applicable_to else None,
        }
        for lbl in result.value
    ]


async def get_data_classifications(limit: int = 100) -> dict:
    """
    Data classification findings — sensitive info types detected in tenant content.
    Returns counts per sensitive information type.
    """
    import httpx
    from src.auth.identity import get_azure_token

    # Compliance center REST API
    token = await get_azure_token("https://graph.microsoft.com/.default")

    async with httpx.AsyncClient(timeout=30) as http:
        resp = await http.get(
            "https://graph.microsoft.com/beta/dataClassification/sensitiveTypes",
            headers={"Authorization": f"Bearer {token}"},
        )

    if resp.status_code != 200:
        return {"error": resp.text, "status": resp.status_code}

    data = resp.json()
    types = data.get("value", [])[:limit]

    return {
        "total_types": len(types),
        "sensitive_types": [
            {
                "id": t.get("id"),
                "name": t.get("name"),
                "description": t.get("description"),
                "publisher": t.get("publisherName"),
                "category": t.get("category"),
                "rule_package_id": t.get("rulePackageId"),
            }
            for t in types
        ],
    }
