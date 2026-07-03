"""M365 Admin Center tools — Microsoft Graph API (tenant settings, MFA, CA)."""

import logging
from src.auth.identity import get_graph_client

logger = logging.getLogger(__name__)


async def get_tenant_security_settings() -> dict:
    """Key tenant-wide security settings from M365 Admin Center."""
    client = get_graph_client()

    # Fetch organisation details + security defaults
    org_result = await client.organization.get()
    org = org_result.value[0] if org_result and org_result.value else None

    # Security defaults (baseline protection)
    import httpx
    from src.auth.identity import get_azure_token
    token = await get_azure_token("https://graph.microsoft.com/.default")

    async with httpx.AsyncClient(timeout=20) as http:
        sd_resp = await http.get(
            "https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy",
            headers={"Authorization": f"Bearer {token}"},
        )
        sd = sd_resp.json() if sd_resp.status_code == 200 else {}

        pw_resp = await http.get(
            "https://graph.microsoft.com/v1.0/domains",
            headers={"Authorization": f"Bearer {token}"},
        )
        domains = pw_resp.json().get("value", []) if pw_resp.status_code == 200 else []

    return {
        "tenant_id": org.id if org else None,
        "display_name": org.display_name if org else None,
        "country": org.country_letter_code if org else None,
        "created": str(org.created_date_time) if org and org.created_date_time else None,
        "security_defaults_enabled": sd.get("isEnabled"),
        "assigned_plans": [
            p.service if hasattr(p, "service") else str(p)
            for p in (org.assigned_plans or [])
        ] if org else [],
        "verified_domains": [
            {"name": d.get("id"), "is_default": d.get("isDefault"), "type": d.get("type")}
            for d in domains
        ],
    }


async def get_mfa_status(limit: int = 200) -> dict:
    """
    MFA adoption across all users — counts enrolled vs not enrolled.
    Returns per-user detail and summary stats.
    """
    import httpx
    from src.auth.identity import get_azure_token

    token = await get_azure_token("https://graph.microsoft.com/.default")

    async with httpx.AsyncClient(timeout=30) as http:
        resp = await http.get(
            f"https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails"
            f"?$top={limit}",
            headers={"Authorization": f"Bearer {token}"},
        )

    if resp.status_code != 200:
        return {"error": resp.text}

    users = resp.json().get("value", [])

    mfa_registered = [u for u in users if u.get("isMfaRegistered")]
    mfa_capable = [u for u in users if u.get("isMfaCapable")]
    sspr_registered = [u for u in users if u.get("isSsprRegistered")]
    admins_without_mfa = [
        u for u in users
        if u.get("isAdmin") and not u.get("isMfaRegistered")
    ]

    return {
        "total_users": len(users),
        "mfa_registered": len(mfa_registered),
        "mfa_registered_pct": round(len(mfa_registered) / len(users) * 100, 1) if users else 0,
        "mfa_capable": len(mfa_capable),
        "sspr_registered": len(sspr_registered),
        "admins_without_mfa": len(admins_without_mfa),
        "admins_without_mfa_detail": [
            {"user": u.get("userPrincipalName"), "is_admin": u.get("isAdmin")}
            for u in admins_without_mfa
        ],
        "users_not_mfa_registered": [
            {"user": u.get("userPrincipalName")}
            for u in users if not u.get("isMfaRegistered")
        ][:50],  # cap to 50 for readability
    }


async def get_conditional_access_policies(limit: int = 50) -> list[dict]:
    """All Conditional Access policies — state, conditions, and grant controls."""
    client = get_graph_client()
    result = await client.identity.conditional_access.policies.get(
        request_configuration=lambda r: setattr(r.query_parameters, "top", limit)
    )
    if not result or not result.value:
        return []

    return [
        {
            "id": p.id,
            "display_name": p.display_name,
            "state": p.state.value if p.state else None,
            "created": str(p.created_date_time) if p.created_date_time else None,
            "modified": str(p.modified_date_time) if p.modified_date_time else None,
            "conditions": {
                "users": {
                    "include_users": p.conditions.users.include_users if p.conditions and p.conditions.users else [],
                    "include_groups": p.conditions.users.include_groups if p.conditions and p.conditions.users else [],
                    "exclude_users": p.conditions.users.exclude_users if p.conditions and p.conditions.users else [],
                },
                "applications": {
                    "include_applications": p.conditions.applications.include_applications if p.conditions and p.conditions.applications else [],
                },
                "platforms": str(p.conditions.platforms) if p.conditions and p.conditions.platforms else None,
                "locations": str(p.conditions.locations) if p.conditions and p.conditions.locations else None,
            },
            "grant_controls": {
                "operator": p.grant_controls.operator if p.grant_controls else None,
                "built_in_controls": [
                    c.value for c in (p.grant_controls.built_in_controls or [])
                ] if p.grant_controls else [],
            },
            "session_controls": str(p.session_controls) if p.session_controls else None,
        }
        for p in result.value
    ]
