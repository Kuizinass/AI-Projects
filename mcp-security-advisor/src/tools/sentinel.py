"""Microsoft Sentinel tools — azure-mgmt-securityinsight + Log Analytics query."""

import logging
from azure.mgmt.securityinsight.aio import SecurityInsights
from azure.monitor.query.aio import LogsQueryClient
from azure.monitor.query import LogsQueryStatus
from src.auth.identity import get_credential
from src.config.settings import settings

logger = logging.getLogger(__name__)


def _sentinel_client() -> SecurityInsights:
    return SecurityInsights(
        credential=get_credential(),
        subscription_id=settings.azure_subscription_id,
    )


async def get_sentinel_incidents(
    severity: str | None = None,
    status: str | None = None,
    limit: int = 50,
) -> list[dict]:
    """
    Active incidents from Microsoft Sentinel.
    severity: 'High', 'Medium', 'Low', 'Informational'
    status: 'New', 'Active', 'Closed'
    """
    client = _sentinel_client()
    results = []
    filters = []
    if severity:
        filters.append(f"properties/severity eq '{severity}'")
    if status:
        filters.append(f"properties/status eq '{status}'")
    filter_str = " and ".join(filters) if filters else None

    async with client:
        async for incident in client.incidents.list(
            resource_group_name=settings.sentinel_resource_group,
            workspace_name=settings.sentinel_workspace_name,
            filter=filter_str,
            top=limit,
        ):
            results.append({
                "id": incident.id,
                "name": incident.name,
                "title": incident.title,
                "description": incident.description,
                "severity": incident.severity,
                "status": incident.status,
                "classification": incident.classification,
                "created": str(incident.created_time_utc) if incident.created_time_utc else None,
                "updated": str(incident.last_modified_time_utc) if incident.last_modified_time_utc else None,
                "alert_count": incident.additional_data.alerts_count if incident.additional_data else 0,
                "assigned_to": incident.owner.assigned_to if incident.owner else None,
            })
    return results


async def get_sentinel_alerts(limit: int = 100) -> list[dict]:
    """Security alerts ingested into Sentinel workspace."""
    client = _sentinel_client()
    results = []
    async with client:
        async for alert in client.alerts.list(
            resource_group_name=settings.sentinel_resource_group,
            workspace_name=settings.sentinel_workspace_name,
        ):
            results.append({
                "id": alert.id,
                "name": alert.name,
                "display_name": alert.alert_display_name,
                "severity": alert.severity,
                "status": alert.status,
                "product_name": alert.product_name,
                "vendor": alert.vendor_name,
                "start_time": str(alert.start_time_utc) if alert.start_time_utc else None,
                "end_time": str(alert.end_time_utc) if alert.end_time_utc else None,
                "description": alert.description,
            })
            if len(results) >= limit:
                break
    return results


async def run_kql_query(query: str, timespan_hours: int = 24) -> dict:
    """
    Execute a KQL query against the Sentinel Log Analytics workspace.
    Returns schema + rows.
    """
    from datetime import timedelta

    client = LogsQueryClient(credential=get_credential())
    async with client:
        response = await client.query_workspace(
            workspace_id=settings.sentinel_workspace_id,
            query=query,
            timespan=timedelta(hours=timespan_hours),
        )

    if response.status == LogsQueryStatus.FAILURE:
        return {"error": str(response.partial_error)}

    table = response.tables[0] if response.tables else None
    if not table:
        return {"rows": [], "schema": []}

    schema = [{"name": c.name, "type": c.type} for c in table.columns]
    rows = [dict(zip([c.name for c in table.columns], row)) for row in table.rows]

    return {"schema": schema, "rows": rows, "row_count": len(rows)}


async def get_analytic_rules(limit: int = 100) -> list[dict]:
    """Review Sentinel analytic (detection) rules."""
    client = _sentinel_client()
    results = []
    async with client:
        async for rule in client.alert_rules.list(
            resource_group_name=settings.sentinel_resource_group,
            workspace_name=settings.sentinel_workspace_name,
        ):
            results.append({
                "id": rule.id,
                "name": rule.name,
                "kind": rule.kind,
                "enabled": getattr(rule, "enabled", None),
                "display_name": getattr(rule, "display_name", None),
                "severity": getattr(rule, "severity", None),
                "description": getattr(rule, "description", None),
                "tactics": getattr(rule, "tactics", []),
                "techniques": getattr(rule, "techniques", []),
            })
            if len(results) >= limit:
                break
    return results
