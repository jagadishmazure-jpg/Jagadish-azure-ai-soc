// Bicep twin of infra/terraform: same resources, same names, same defaults.
// Deploy: az deployment sub create --location eastus2 --template-file infra/bicep/main.bicep --parameters environment=dev
targetScope = 'subscription'

@allowed(['dev', 'prod'])
param environment string

@allowed(['eastus2', 'westus2', 'westeurope'])
param location string = 'eastus2'

@description('Short name of the customer tenant this workspace serves (one workspace per customer tenant).')
@minLength(3)
@maxLength(16)
param tenantSlug string = 'brightwater'

param retentionInDays int = 90
param dailyQuotaGb int = 1

@description('Create the scheduled analytics rules from detections/rules.json (off by default; see docs/infra/sentinel-workspace.md).')
param deployAnalyticsRules bool = false
param analyticsRulesEnabled bool = false

@description('HTTPS endpoint of the triage agent. Empty: the playbook has no HTTP action.')
param agentEndpoint string = ''
param agentAudience string = 'api://aisoc-agent'
param enableAutomationRule bool = false
param privateNetworking bool = false
param vnetAddressSpace string = '10.40.0.0/24'

var shortLocation = {
  eastus2: 'eus2'
  westus2: 'wus2'
  westeurope: 'weu'
}
var suffix = '${tenantSlug}-${environment}-${shortLocation[location]}'
var tags = {
  workload: 'aisoc'
  environment: environment
  tenant: tenantSlug
  managed_by: 'bicep'
  data: 'security-telemetry'
}

resource rg 'Microsoft.Resources/resourceGroups@2024-03-01' = {
  name: 'rg-aisoc-${suffix}-001'
  location: location
  tags: tags
}

module workspace 'modules/workspace.bicep' = {
  name: 'workspace'
  scope: rg
  params: {
    suffix: suffix
    location: location
    tags: tags
    retentionInDays: retentionInDays
    dailyQuotaGb: dailyQuotaGb
    privateNetworking: privateNetworking
    deployAnalyticsRules: deployAnalyticsRules
    analyticsRulesEnabled: analyticsRulesEnabled
  }
}

module identity 'modules/identity.bicep' = {
  name: 'identity'
  scope: rg
  params: {
    suffix: suffix
    location: location
    tags: tags
    workspaceName: workspace.outputs.name
  }
}

module playbook 'modules/playbook.bicep' = {
  name: 'playbook'
  scope: rg
  params: {
    suffix: suffix
    location: location
    tags: tags
    tenantSlug: tenantSlug
    workspaceName: workspace.outputs.name
    playbookIdentityId: identity.outputs.playbookIdentityId
    agentEndpoint: agentEndpoint
    agentAudience: agentAudience
    enableAutomationRule: enableAutomationRule
  }
}

module network 'modules/network.bicep' = if (privateNetworking) {
  name: 'network'
  scope: rg
  params: {
    suffix: suffix
    location: location
    tags: tags
    workspaceId: workspace.outputs.id
    vnetAddressSpace: vnetAddressSpace
  }
}

output AZURE_RESOURCE_GROUP string = rg.name
output LOG_ANALYTICS_WORKSPACE_NAME string = workspace.outputs.name
output LOG_ANALYTICS_WORKSPACE_ID string = workspace.outputs.id
output PLAYBOOK_ID string = playbook.outputs.id
output AGENT_IDENTITY_CLIENT_ID string = identity.outputs.agentClientId
