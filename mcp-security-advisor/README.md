# MP Cyber Security Advisor — MCP Server

> An autonomous AI security advisor that connects Claude to the full Microsoft security stack. Reviews your security posture, identifies misconfigurations and vulnerabilities, auto-remediates low-risk issues, and escalates everything else to your security analysts via Microsoft Teams.

Built by [MP Cybersecurity](https://mpcybersecurity.co.uk) — fractional CISO services for SMBs and scale-ups.

---

## What Is This?

This is a **Model Context Protocol (MCP) server** hosted on Azure that gives Claude direct access to your Microsoft security tooling. Instead of logging into five different portals to understand your security posture, you ask Claude — and it queries, analyses, and acts across your entire stack in one conversation.

**Connects to:**
- Microsoft Defender XDR (incidents, alerts, advanced hunting, CVEs)
- Microsoft Defender for Cloud (recommendations, compliance, posture)
- Microsoft Sentinel (incidents, alerts, KQL queries, analytic rules)
- Microsoft Intune (device compliance, configuration policies)
- Microsoft Purview (DLP alerts, sensitivity labels, data classifications)
- M365 Admin Center (tenant settings, MFA status, Conditional Access)
- Microsoft Secure Score (score, controls, history)

**What it can do:**
- Pull your current Secure Score and identify the controls with the biggest gaps
- List open incidents and alerts across Defender XDR and Sentinel
- Run KQL queries against your Sentinel workspace
- Review device compliance and flag non-compliant endpoints
- Check MFA adoption and identify admins without MFA
- Review all Conditional Access policies
- Assess and remediate misconfigurations with full risk reasoning
- Automatically fix low-risk issues; escalate medium/high-risk actions to Teams
- Generate structured action plans for security analysts

---

## Architecture

```
Claude Desktop / Claude Code
          │  MCP (HTTP/SSE)
          ▼
┌─────────────────────────────────────────────────────┐
│         MCP Security Advisor (Azure Container Apps)  │
│                                                      │
│  ┌──────────────┐   ┌──────────────┐               │
│  │  Auth Module  │   │  Risk Engine  │               │
│  │ (Managed ID) │   │  (0–100 score)│               │
│  └──────┬───────┘   └──────┬───────┘               │
│         │                  │                         │
│  ┌──────▼──────────────────▼──────────────────┐    │
│  │              Tool Layer (28 tools)           │    │
│  │  Secure Score │ Defender XDR │ Sentinel      │    │
│  │  Defender Cloud │ Intune │ Purview │ Admin   │    │
│  └──────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────┘
          │                          │
          ▼                          ▼
  Microsoft Graph API          Azure Management API
  (M365 security stack)        (Defender for Cloud,
                                Sentinel, Azure RBAC)
          │
          ▼
  Microsoft Teams Webhook
  (escalation + approval cards)
```

### Risk Gate

Every write action passes through the risk engine before execution:

| Score | Level | Action |
|-------|-------|--------|
| 0–30 | LOW | Auto-execute immediately |
| 31–70 | MEDIUM | Send Teams approval card → await analyst decision |
| 71–90 | HIGH | Escalate to Teams, never execute |
| 91–100 | CRITICAL | Immediate escalation, blocked entirely |

Risk score is calculated from: affected scope, reversibility, service criticality, data sensitivity, change frequency, and platform severity rating.

### Security Design

- **Zero stored credentials** — Azure Managed Identity only; no secrets in code or environment variables
- **Private networking** — Key Vault on private endpoint, VNet-integrated Container Apps
- **Least privilege** — minimum Graph API permissions, scoped Azure RBAC roles
- **Audit trail** — every write action logged to Log Analytics with risk score and outcome
- **Non-root container** — runs as unprivileged user inside Docker
- **TLS enforced** — no HTTP, TLS 1.3 only on Container Apps ingress

---

## Prerequisites

- Azure subscription with Owner or Contributor + User Access Administrator rights
- Microsoft 365 tenant (E3/E5 or equivalent licences for the security products)
- Microsoft Sentinel workspace already deployed
- Azure CLI installed locally (`az --version`)
- Docker installed locally (for building the image)
- Claude Desktop or Claude Code (to connect the MCP server)
- A Microsoft Teams channel with an Incoming Webhook configured

---

## Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/Kuizinass/AI-Projects.git
cd AI-Projects/mcp-security-advisor
```

### 2. Configure environment variables

```bash
cp .env.example .env
```

Edit `.env` with your values:

```env
AZURE_TENANT_ID=your-tenant-id
AZURE_SUBSCRIPTION_ID=your-subscription-id
SENTINEL_WORKSPACE_ID=your-log-analytics-workspace-id
SENTINEL_WORKSPACE_NAME=your-sentinel-workspace-name
SENTINEL_RESOURCE_GROUP=your-resource-group-name
TEAMS_WEBHOOK_URL=https://your-org.webhook.office.com/webhookb2/...
```

### 3. Deploy Azure infrastructure

```bash
# Login to Azure
az login

# Create a resource group
az group create --name rg-mcp-security --location uksouth

# Deploy the Bicep template
az deployment group create \
  --resource-group rg-mcp-security \
  --template-file infra/main.bicep \
  --parameters \
    environment=prod \
    sentinelWorkspaceId="<your-workspace-id>" \
    sentinelWorkspaceName="<your-workspace-name>" \
    sentinelResourceGroup="<your-sentinel-rg>" \
    teamsWebhookUrl="<your-webhook-url>"
```

### 4. Build and push the Docker image

```bash
# Get the ACR name from the deployment output (or use your own ACR)
ACR_NAME="<your-acr-name>"

az acr login --name $ACR_NAME

docker build -t $ACR_NAME.azurecr.io/mcp-security-advisor:latest .
docker push $ACR_NAME.azurecr.io/mcp-security-advisor:latest
```

### 5. Grant Microsoft Graph API permissions

The managed identity needs Graph API application permissions. Run this once after deployment:

```bash
# Get the managed identity's service principal object ID from deployment output
MANAGED_IDENTITY_PRINCIPAL_ID="<from deployment output: managedIdentityPrincipalId>"
GRAPH_APP_ID="00000003-0000-0000-c000-000000000000"

# Required permissions
PERMISSIONS=(
  "bf394140-e372-4bf9-a898-299cfc7564e5"  # SecurityEvents.ReadWrite.All
  "d903a879-88e0-4c09-b0c9-82f6a1333f84"  # SecurityIncident.ReadWrite.All
  "93489bf5-0fbc-4f2d-b901-33f2fe08ff05"  # SecurityAlert.ReadWrite.All
  "b0afded3-3588-46d8-8b3d-9842eff778da"  # AuditLog.Read.All
  "e0b77adb-e790-44a3-b0a0-257d06303687"  # SecureScore.Read.All
  "dc377aa6-52d8-4e23-dc93-8336d2ae4c0b"  # DeviceManagementManagedDevices.ReadWrite.All
  "9241abd9-d0e6-425a-bd4f-47ba86e767a4"  # DeviceManagementConfiguration.ReadWrite.All
  "62a82d76-70ea-41e2-9197-370581804d09"  # Group.ReadWrite.All
  "246dd0d5-5bd0-4def-940b-0421030a5b68"  # Policy.Read.All
  "7ab1d382-f21e-4acd-a863-ba3e13f7da61"  # Directory.Read.All
  "e4c9e354-4dc5-45b8-9e7c-e1393b0b1a20"  # InformationProtectionPolicy.Read.All
)

for PERM in "${PERMISSIONS[@]}"; do
  az ad app permission add \
    --id $MANAGED_IDENTITY_PRINCIPAL_ID \
    --api $GRAPH_APP_ID \
    --api-permissions "$PERM=Role"
done

# Grant admin consent
az ad app permission admin-consent --id $MANAGED_IDENTITY_PRINCIPAL_ID
```

### 6. Grant Sentinel roles

```bash
SENTINEL_SCOPE="/subscriptions/<subId>/resourceGroups/<rg>/providers/Microsoft.OperationalInsights/workspaces/<workspace>"

az role assignment create \
  --assignee $MANAGED_IDENTITY_PRINCIPAL_ID \
  --role "Microsoft Sentinel Responder" \
  --scope $SENTINEL_SCOPE
```

### 7. Connect to Claude Desktop

Add to your `claude_desktop_config.json`:

**macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
**Windows:** `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "mp-security-advisor": {
      "url": "https://<your-container-app-fqdn>",
      "transport": "http"
    }
  }
}
```

Restart Claude Desktop. You should see the security advisor tools available.

---

## Available Tools (28)

### Secure Score
| Tool | Description |
|------|-------------|
| `get_secure_score` | Current score, percentage, and metadata |
| `list_secure_score_controls` | All controls sorted by largest gap, with remediation guidance |
| `get_secure_score_history` | Score trend over 1–90 days |

### Microsoft Defender XDR
| Tool | Description |
|------|-------------|
| `get_incidents` | Active incidents, filterable by severity |
| `get_alerts` | Security alerts across M365 Defender |
| `run_advanced_hunting` | Execute KQL against M365 Defender Advanced Hunting |
| `get_vulnerabilities` | CVE findings per device from Defender for Endpoint |

### Microsoft Defender for Cloud
| Tool | Description |
|------|-------------|
| `get_security_posture` | Overall posture summary and secure scores |
| `get_recommendations` | All recommendations with severity |
| `get_compliance_status` | Regulatory compliance (NIST, CIS, PCI DSS, etc.) |
| `remediate_recommendation` | ⚡ Apply a fix — risk-gated, escalates to Teams if needed |

### Microsoft Sentinel
| Tool | Description |
|------|-------------|
| `get_sentinel_incidents` | Incidents filterable by severity and status |
| `get_sentinel_alerts` | Security alerts in the Sentinel workspace |
| `run_kql_query` | Execute KQL against Log Analytics |
| `get_analytic_rules` | Review detection rules with MITRE tactics |

### Microsoft Intune
| Tool | Description |
|------|-------------|
| `get_device_compliance` | Compliance status per device |
| `get_noncompliant_devices` | All devices currently failing policies |
| `get_configuration_policies` | Review configuration policies |
| `apply_compliance_policy` | ⚡ Assign policy to device group — risk-gated |

### Microsoft Purview
| Tool | Description |
|------|-------------|
| `get_dlp_alerts` | Data Loss Prevention violations |
| `get_sensitivity_labels` | Configured sensitivity labels |
| `get_data_classifications` | Sensitive information types detected |

### M365 Admin Center
| Tool | Description |
|------|-------------|
| `get_tenant_security_settings` | Tenant-wide settings including security defaults |
| `get_mfa_status` | MFA adoption — registered count, percentage, admins without MFA |
| `get_conditional_access_policies` | All CA policies with conditions and grant controls |

### Risk & Escalation
| Tool | Description |
|------|-------------|
| `assess_risk` | Score any proposed action 0–100 with written reasoning |
| `create_action_plan` | Generate a structured remediation plan for analyst review |
| `escalate_to_analyst` | Post a Teams card to the security channel |

> ⚡ = write action, passes through risk gate

---

## Example Conversations

**Security posture review:**
> "What is our current Secure Score and what are the top 5 controls we should fix first?"

**Incident triage:**
> "Are there any High severity incidents open in Defender XDR right now? Give me a summary."

**MFA gap:**
> "Check our MFA status — who are the admins without MFA registered and what's our overall adoption rate?"

**Misconfiguration fix:**
> "Get our Defender for Cloud recommendations and remediate any Low severity ones automatically."

**KQL investigation:**
> "Run a KQL query in Sentinel to find all failed sign-in attempts from outside the UK in the last 24 hours."

**Full posture report:**
> "Give me a complete security posture report covering Secure Score, open incidents, non-compliant devices, and any DLP alerts from the past week."

---

## Local Development

```bash
# Install dependencies
pip install -r requirements.txt

# For local dev, set service principal credentials in .env
# (In production, Managed Identity handles this automatically)
AZURE_CLIENT_ID=your-sp-client-id
AZURE_CLIENT_SECRET=your-sp-client-secret

# Run the server locally
python -m src.server

# Run tests (no live credentials needed)
pytest tests/ -v
```

---

## Project Structure

```
mcp-security-advisor/
├── src/
│   ├── server.py              # FastMCP entry point — all 28 tools registered
│   ├── auth/
│   │   └── identity.py        # Managed Identity token acquisition
│   ├── config/
│   │   └── settings.py        # Environment variable config
│   ├── risk/
│   │   ├── engine.py          # Risk scoring logic (0–100)
│   │   └── thresholds.py      # Configurable LOW/MEDIUM/HIGH/CRITICAL bands
│   └── tools/
│       ├── secure_score.py    # Microsoft Secure Score
│       ├── defender_xdr.py    # Defender XDR / M365 Defender
│       ├── defender_cloud.py  # Defender for Cloud (+ remediation)
│       ├── sentinel.py        # Microsoft Sentinel
│       ├── intune.py          # Microsoft Intune (+ policy assignment)
│       ├── purview.py         # Microsoft Purview
│       ├── admin_center.py    # M365 Admin Center
│       └── escalation.py      # Teams Adaptive Card escalation
├── infra/
│   ├── main.bicep             # Top-level Azure IaC
│   └── modules/
│       ├── container_app.bicep
│       ├── keyvault.bicep
│       ├── monitoring.bicep
│       └── network.bicep
├── tests/
│   ├── test_risk_engine.py    # 15 unit tests — no credentials needed
│   └── test_tools.py          # Integration tests with mocked Azure calls
├── Dockerfile
├── requirements.txt
└── .env.example
```

---

## Built By

**MP Cybersecurity** — fractional CISO and vCISO services

- Website: [mpcybersecurity.co.uk](https://mpcybersecurity.co.uk)
- Email: mp@mpcybersecurity.co.uk
- Founder: Marius Poskus, CISM

---

## Licence

MIT — free to use, modify, and deploy. Attribution appreciated.
