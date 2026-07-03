"""Microsoft Intune tools — Microsoft Graph API (Device Management)."""

import logging
import uuid
from src.auth.identity import get_graph_client
from src.risk.engine import ActionContext, score_action
from src.risk.thresholds import RiskLevel
from src.tools.escalation import send_escalation_card

logger = logging.getLogger(__name__)


async def get_device_compliance(limit: int = 100) -> list[dict]:
    """Compliance status for all managed devices."""
    client = get_graph_client()
    result = await client.device_management.managed_devices.get(
        request_configuration=lambda r: setattr(r.query_parameters, "top", limit)
    )
    if not result or not result.value:
        return []

    return [
        {
            "id": d.id,
            "device_name": d.device_name,
            "user_principal_name": d.user_principal_name,
            "os": d.operating_system,
            "os_version": d.os_version,
            "compliance_state": d.compliance_state.value if d.compliance_state else None,
            "management_state": d.management_state.value if d.management_state else None,
            "last_sync": str(d.last_sync_date_time) if d.last_sync_date_time else None,
            "enrolled": str(d.enrolled_date_time) if d.enrolled_date_time else None,
            "jail_broken": d.jail_broken,
            "manufacturer": d.manufacturer,
            "model": d.model,
        }
        for d in result.value
    ]


async def get_noncompliant_devices() -> list[dict]:
    """Devices that are failing compliance policies."""
    client = get_graph_client()
    result = await client.device_management.managed_devices.get(
        request_configuration=lambda r: setattr(
            r.query_parameters, "filter", "complianceState eq 'noncompliant'"
        )
    )
    if not result or not result.value:
        return []

    return [
        {
            "id": d.id,
            "device_name": d.device_name,
            "user_principal_name": d.user_principal_name,
            "os": d.operating_system,
            "os_version": d.os_version,
            "last_sync": str(d.last_sync_date_time) if d.last_sync_date_time else None,
            "jail_broken": d.jail_broken,
        }
        for d in result.value
    ]


async def get_configuration_policies(limit: int = 50) -> list[dict]:
    """Review device configuration policies in Intune."""
    client = get_graph_client()
    result = await client.device_management.device_configurations.get(
        request_configuration=lambda r: setattr(r.query_parameters, "top", limit)
    )
    if not result or not result.value:
        return []

    return [
        {
            "id": c.id,
            "display_name": c.display_name,
            "description": c.description,
            "created": str(c.created_date_time) if c.created_date_time else None,
            "modified": str(c.last_modified_date_time) if c.last_modified_date_time else None,
            "odata_type": c.odata_type,
        }
        for c in result.value
    ]


async def apply_compliance_policy(
    policy_id: str,
    policy_name: str,
    target_group_id: str,
    affected_device_count: int,
    total_device_count: int,
    is_reversible: bool = True,
    service_critical: bool = False,
) -> dict:
    """
    Assign a compliance policy to a device group.
    Passes through the risk gate — auto-executes if LOW, escalates otherwise.
    """
    action_id = str(uuid.uuid4())
    description = f"Assign compliance policy '{policy_name}' to group {target_group_id}"

    ctx = ActionContext(
        action_type="apply_compliance_policy",
        description=description,
        affected_resource=f"policy/{policy_id}",
        affected_count=affected_device_count,
        total_count=total_device_count,
        is_reversible=is_reversible,
        service_critical=service_critical,
        touches_pii=False,
        recently_changed=False,
        severity="Medium",
    )

    risk = score_action(ctx)
    portal_url = "https://intune.microsoft.com/#view/Microsoft_Intune_DeviceSettings/DevicesMenu"

    if risk.level == RiskLevel.LOW:
        from msgraph.generated.device_management.device_configurations.item.assign.assign_post_request_body import (
            AssignPostRequestBody,
        )
        from msgraph.generated.models.device_configuration_assignment import DeviceConfigurationAssignment
        from msgraph.generated.models.device_and_app_management_assignment_target import DeviceAndAppManagementAssignmentTarget

        client = get_graph_client()
        assignment = DeviceConfigurationAssignment()
        target = DeviceAndAppManagementAssignmentTarget()
        target.odata_type = "#microsoft.graph.groupAssignmentTarget"
        target.additional_data = {"groupId": target_group_id}
        assignment.target = target

        body = AssignPostRequestBody(assignments=[assignment])
        await client.device_management.device_configurations.by_device_configuration_id(
            policy_id
        ).assign.post(body)

        return {
            "action_id": action_id,
            "outcome": "executed",
            "risk_level": risk.level.value,
            "risk_score": risk.score,
            "reasoning": risk.reasoning,
        }

    elif risk.level == RiskLevel.MEDIUM:
        await send_escalation_card(
            action_id=action_id,
            action_description=description,
            affected_resource=f"Policy: {policy_name}",
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
            affected_resource=f"Policy: {policy_name}",
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
