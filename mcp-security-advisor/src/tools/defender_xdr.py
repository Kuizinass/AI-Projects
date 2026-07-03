"""Defender XDR (M365 Defender) tools — Microsoft Graph Security API."""

import logging
from src.auth.identity import get_graph_client

logger = logging.getLogger(__name__)


async def get_incidents(severity: str | None = None, limit: int = 50) -> list[dict]:
    """
    Active security incidents from Defender XDR.
    severity: filter by 'high', 'medium', 'low', 'informational' (optional)
    """
    client = get_graph_client()

    def configure(r):
        r.query_parameters.top = limit
        if severity:
            r.query_parameters.filter = f"severity eq '{severity}'"

    result = await client.security.incidents.get(request_configuration=configure)
    if not result or not result.value:
        return []

    return [
        {
            "id": i.id,
            "display_name": i.display_name,
            "severity": i.severity.value if i.severity else None,
            "status": i.status.value if i.status else None,
            "classification": i.classification.value if i.classification else None,
            "created": str(i.created_date_time),
            "updated": str(i.last_update_date_time),
            "alert_count": len(i.alerts) if i.alerts else 0,
            "assigned_to": i.assigned_to,
            "tags": i.tags or [],
        }
        for i in result.value
    ]


async def get_alerts(severity: str | None = None, limit: int = 100) -> list[dict]:
    """Security alerts from Microsoft 365 Defender."""
    client = get_graph_client()

    def configure(r):
        r.query_parameters.top = limit
        if severity:
            r.query_parameters.filter = f"severity eq '{severity}'"

    result = await client.security.alerts_v2.get(request_configuration=configure)
    if not result or not result.value:
        return []

    return [
        {
            "id": a.id,
            "title": a.title,
            "severity": a.severity.value if a.severity else None,
            "status": a.status.value if a.status else None,
            "category": a.category,
            "service_source": a.service_source.value if a.service_source else None,
            "detection_source": a.detection_source.value if a.detection_source else None,
            "created": str(a.created_date_time),
            "description": a.description,
            "recommended_actions": a.recommended_actions,
            "mitre_techniques": a.mitre_techniques or [],
        }
        for a in result.value
    ]


async def run_advanced_hunting(query: str) -> dict:
    """
    Execute a KQL query against Microsoft 365 Defender Advanced Hunting.
    Returns up to 1000 rows.
    """
    from msgraph.generated.security.microsoft_graph_security_run_hunting_query.run_hunting_query_post_request_body import (
        RunHuntingQueryPostRequestBody,
    )

    client = get_graph_client()
    body = RunHuntingQueryPostRequestBody(query=query)
    result = await client.security.microsoft_graph_security_run_hunting_query.post(body)

    if not result:
        return {"rows": [], "schema": []}

    return {
        "schema": [{"name": c.name, "type": c.type} for c in (result.schema or [])],
        "rows": result.results or [],
        "row_count": len(result.results) if result.results else 0,
    }


async def get_vulnerabilities(device_name: str | None = None, limit: int = 100) -> list[dict]:
    """
    CVE vulnerabilities from Defender for Endpoint (via Graph).
    Optionally filter by device name.
    """
    import httpx
    from src.auth.identity import get_azure_token

    token = await get_azure_token("https://api.securitycenter.microsoft.com/.default")
    url = "https://api.securitycenter.microsoft.com/api/vulnerabilities/machinesVulnerabilities"
    params: dict = {"$top": limit}
    if device_name:
        params["$filter"] = f"computerDnsName eq '{device_name}'"

    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.get(
            url,
            headers={"Authorization": f"Bearer {token}"},
            params=params,
        )
        resp.raise_for_status()
        data = resp.json()

    return data.get("value", [])
