@description('Location for all resources')
param location string

@description('Environment name')
param environment string

@description('Container image to deploy (e.g. acrname.azurecr.io/mcp-security-advisor:latest)')
param containerImage string

@description('Subnet ID for Container Apps environment')
param containerAppsSubnetId string

@description('Log Analytics workspace ID')
param logAnalyticsWorkspaceId string

@description('Log Analytics workspace customer ID (for CA env)')
param logAnalyticsWorkspaceName string

@description('Application Insights connection string')
param appInsightsConnectionString string

@description('Key Vault URI')
param keyVaultUri string

@description('Azure Tenant ID')
param tenantId string

@description('Azure Subscription ID')
param subscriptionId string

@description('Sentinel workspace ID')
param sentinelWorkspaceId string

@description('Sentinel workspace name')
param sentinelWorkspaceName string

@description('Sentinel resource group name')
param sentinelResourceGroup string

@description('Teams webhook URL (stored in Key Vault, referenced as secret)')
@secure()
param teamsWebhookUrl string

resource logAnalytics 'Microsoft.OperationalInsights/workspaces@2022-10-01' existing = {
  name: logAnalyticsWorkspaceName
}

// User-assigned managed identity for the MCP server
resource managedIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: 'id-mcp-security-${environment}'
  location: location
}

// Container Apps Environment (VNet integrated)
resource containerAppsEnv 'Microsoft.App/managedEnvironments@2024-03-01' = {
  name: 'cae-mcp-security-${environment}'
  location: location
  properties: {
    appLogsConfiguration: {
      destination: 'log-analytics'
      logAnalyticsConfiguration: {
        customerId: logAnalytics.properties.customerId
        sharedKey: logAnalytics.listKeys().primarySharedKey
      }
    }
    vnetConfiguration: {
      infrastructureSubnetId: containerAppsSubnetId
      internal: false   // set true if behind API Management / private only
    }
    workloadProfiles: [
      {
        name: 'Consumption'
        workloadProfileType: 'Consumption'
      }
    ]
  }
}

// Container App
resource containerApp 'Microsoft.App/containerApps@2024-03-01' = {
  name: 'ca-mcp-security-${environment}'
  location: location
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${managedIdentity.id}': {}
    }
  }
  properties: {
    managedEnvironmentId: containerAppsEnv.id
    workloadProfileName: 'Consumption'
    configuration: {
      ingress: {
        external: true
        targetPort: 8080
        transport: 'http'
        allowInsecure: false       // HTTPS only
        traffic: [{ weight: 100, latestRevision: true }]
      }
      secrets: [
        {
          name: 'teams-webhook-url'
          value: teamsWebhookUrl
        }
      ]
    }
    template: {
      containers: [
        {
          name: 'mcp-security-advisor'
          image: containerImage
          resources: {
            cpu: json('0.5')
            memory: '1Gi'
          }
          env: [
            { name: 'AZURE_TENANT_ID', value: tenantId }
            { name: 'AZURE_SUBSCRIPTION_ID', value: subscriptionId }
            { name: 'AZURE_CLIENT_ID', value: managedIdentity.properties.clientId }
            { name: 'SENTINEL_WORKSPACE_ID', value: sentinelWorkspaceId }
            { name: 'SENTINEL_WORKSPACE_NAME', value: sentinelWorkspaceName }
            { name: 'SENTINEL_RESOURCE_GROUP', value: sentinelResourceGroup }
            { name: 'APPLICATIONINSIGHTS_CONNECTION_STRING', value: appInsightsConnectionString }
            { name: 'TEAMS_WEBHOOK_URL', secretRef: 'teams-webhook-url' }
            { name: 'LOG_LEVEL', value: 'INFO' }
          ]
          probes: [
            {
              type: 'Liveness'
              httpGet: {
                path: '/health'
                port: 8080
              }
              initialDelaySeconds: 10
              periodSeconds: 30
            }
            {
              type: 'Readiness'
              httpGet: {
                path: '/health'
                port: 8080
              }
              initialDelaySeconds: 5
              periodSeconds: 10
            }
          ]
        }
      ]
      scale: {
        minReplicas: 1
        maxReplicas: 3
        rules: [
          {
            name: 'http-scaling'
            http: { metadata: { concurrentRequests: '10' } }
          }
        ]
      }
    }
  }
}

output managedIdentityPrincipalId string = managedIdentity.properties.principalId
output managedIdentityClientId string = managedIdentity.properties.clientId
output containerAppFqdn string = containerApp.properties.configuration.ingress.fqdn
output containerAppName string = containerApp.name
