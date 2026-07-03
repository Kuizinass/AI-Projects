/*
  MP Cyber Security Advisor — Azure Infrastructure
  Deploys: VNet, Key Vault, Log Analytics, App Insights, Container Apps
  Auth: Managed Identity (no stored credentials in code)
*/

@description('Azure region for all resources')
param location string = resourceGroup().location

@description('Environment name: prod or dev')
@allowed(['prod', 'dev'])
param environment string = 'prod'

@description('Container image to deploy')
param containerImage string = 'mcpsecurityadvisor.azurecr.io/mcp-security-advisor:latest'

@description('Azure Tenant ID')
param tenantId string = subscription().tenantId

@description('Azure Subscription ID')
param subscriptionId string = subscription().subscriptionId

@description('Sentinel workspace ID (Log Analytics workspace ID)')
param sentinelWorkspaceId string

@description('Sentinel workspace name')
param sentinelWorkspaceName string

@description('Sentinel resource group name')
param sentinelResourceGroup string

@description('Teams Incoming Webhook URL (treated as secure)')
@secure()
param teamsWebhookUrl string

// ── Networking ────────────────────────────────────────────────
module network 'modules/network.bicep' = {
  name: 'network-${environment}'
  params: {
    location: location
    environment: environment
  }
}

// ── Monitoring ────────────────────────────────────────────────
module monitoring 'modules/monitoring.bicep' = {
  name: 'monitoring-${environment}'
  params: {
    location: location
    environment: environment
  }
}

// ── Container App + Managed Identity ─────────────────────────
module containerApp 'modules/container_app.bicep' = {
  name: 'container-app-${environment}'
  params: {
    location: location
    environment: environment
    containerImage: containerImage
    containerAppsSubnetId: network.outputs.containerAppsSubnetId
    logAnalyticsWorkspaceId: monitoring.outputs.logAnalyticsWorkspaceId
    logAnalyticsWorkspaceName: monitoring.outputs.logAnalyticsWorkspaceName
    appInsightsConnectionString: monitoring.outputs.appInsightsConnectionString
    keyVaultUri: keyVault.outputs.keyVaultUri
    tenantId: tenantId
    subscriptionId: subscriptionId
    sentinelWorkspaceId: sentinelWorkspaceId
    sentinelWorkspaceName: sentinelWorkspaceName
    sentinelResourceGroup: sentinelResourceGroup
    teamsWebhookUrl: teamsWebhookUrl
  }
}

// ── Key Vault (depends on managed identity from container app) ─
module keyVault 'modules/keyvault.bicep' = {
  name: 'keyvault-${environment}'
  params: {
    location: location
    environment: environment
    managedIdentityPrincipalId: containerApp.outputs.managedIdentityPrincipalId
    privateEndpointSubnetId: network.outputs.privateEndpointsSubnetId
    vnetId: network.outputs.vnetId
  }
}

// ── Azure RBAC: grant Managed Identity security roles ─────────

// Security Reader — Defender for Cloud + Sentinel
resource securityReaderRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(subscription().id, containerApp.outputs.managedIdentityPrincipalId, 'security-reader')
  properties: {
    roleDefinitionId: subscriptionResourceId(
      'Microsoft.Authorization/roleDefinitions',
      '39bc4728-0917-49c7-9d2c-d95423bc2eb4' // Security Reader
    )
    principalId: containerApp.outputs.managedIdentityPrincipalId
    principalType: 'ServicePrincipal'
  }
}

// Security Admin — for Defender for Cloud remediation actions
resource securityAdminRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(subscription().id, containerApp.outputs.managedIdentityPrincipalId, 'security-admin')
  properties: {
    roleDefinitionId: subscriptionResourceId(
      'Microsoft.Authorization/roleDefinitions',
      'fb1c8493-542b-48eb-b624-b4c8fea62acd' // Security Admin
    )
    principalId: containerApp.outputs.managedIdentityPrincipalId
    principalType: 'ServicePrincipal'
  }
}

// ── Outputs ────────────────────────────────────────────────────
output mcpServerUrl string = 'https://${containerApp.outputs.containerAppFqdn}'
output managedIdentityClientId string = containerApp.outputs.managedIdentityClientId
output managedIdentityPrincipalId string = containerApp.outputs.managedIdentityPrincipalId
output keyVaultUri string = keyVault.outputs.keyVaultUri
output logAnalyticsWorkspaceName string = monitoring.outputs.logAnalyticsWorkspaceName
output appInsightsConnectionString string = monitoring.outputs.appInsightsConnectionString

/*
  POST-DEPLOYMENT STEPS (manual, one-time):
  ==========================================
  1. Grant Graph API permissions to the managed identity in Entra ID:
     az ad app permission add --id <managedIdentityClientId> \
       --api 00000003-0000-0000-c000-000000000000 \
       --api-permissions <see README for full permission list>

  2. Grant admin consent:
     az ad app permission admin-consent --id <managedIdentityClientId>

  3. Assign Sentinel Responder role on the Sentinel workspace:
     az role assignment create \
       --assignee <managedIdentityPrincipalId> \
       --role "Microsoft Sentinel Responder" \
       --scope /subscriptions/<subId>/resourceGroups/<rg>/providers/...

  4. Connect Claude Desktop to the MCP server:
     Add to claude_desktop_config.json:
     {
       "mcpServers": {
         "mp-security-advisor": {
           "url": "<mcpServerUrl>",
           "transport": "http"
         }
       }
     }
*/
