@description('Location for all resources')
param location string

@description('Environment name')
param environment string

resource logAnalytics 'Microsoft.OperationalInsights/workspaces@2022-10-01' = {
  name: 'law-mcp-security-${environment}'
  location: location
  properties: {
    sku: { name: 'PerGB2018' }
    retentionInDays: 90
    features: {
      enableLogAccessUsingOnlyResourcePermissions: true
    }
    publicNetworkAccessForIngestion: 'Enabled'
    publicNetworkAccessForQuery: 'Enabled'
  }
}

resource appInsights 'Microsoft.Insights/components@2020-02-02' = {
  name: 'appi-mcp-security-${environment}'
  location: location
  kind: 'web'
  properties: {
    Application_Type: 'web'
    WorkspaceResourceId: logAnalytics.id
    IngestionMode: 'LogAnalytics'
    publicNetworkAccessForIngestion: 'Enabled'
    publicNetworkAccessForQuery: 'Enabled'
  }
}

// Diagnostic: capture all MCP write-action audit events in a dedicated table
resource auditTable 'Microsoft.OperationalInsights/workspaces/tables@2022-10-01' = {
  parent: logAnalytics
  name: 'McpSecurityAudit_CL'
  properties: {
    schema: {
      name: 'McpSecurityAudit_CL'
      columns: [
        { name: 'TimeGenerated', type: 'datetime' }
        { name: 'ActionId', type: 'string' }
        { name: 'ActionType', type: 'string' }
        { name: 'Description', type: 'string' }
        { name: 'AffectedResource', type: 'string' }
        { name: 'RiskScore', type: 'int' }
        { name: 'RiskLevel', type: 'string' }
        { name: 'Outcome', type: 'string' }
        { name: 'Reasoning', type: 'string' }
      ]
    }
    retentionInDays: 365   // 1-year audit retention
  }
}

output logAnalyticsWorkspaceId string = logAnalytics.id
output logAnalyticsWorkspaceName string = logAnalytics.name
output appInsightsConnectionString string = appInsights.properties.ConnectionString
output appInsightsInstrumentationKey string = appInsights.properties.InstrumentationKey
