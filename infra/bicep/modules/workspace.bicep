// Log Analytics workspace, Microsoft Sentinel onboarding, the scheduled analytics rules from
// detections/rules.json, and a diagnostic setting that audits queries against the workspace.
param suffix string
param location string
param tags object
param retentionInDays int
param dailyQuotaGb int
param privateNetworking bool
param deployAnalyticsRules bool
param analyticsRulesEnabled bool

var rules = loadJsonContent('../../../detections/rules.json').rules
var entityTypes = {
  account: { type: 'Account', identifier: 'FullName' }
  host: { type: 'Host', identifier: 'HostName' }
  ip: { type: 'IP', identifier: 'Address' }
  url: { type: 'URL', identifier: 'Url' }
}

resource law 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: 'law-aisoc-${suffix}'
  location: location
  tags: tags
  properties: {
    sku: { name: 'PerGB2018' }
    retentionInDays: retentionInDays
    workspaceCapping: { dailyQuotaGb: dailyQuotaGb }
    publicNetworkAccessForIngestion: privateNetworking ? 'Disabled' : 'Enabled'
    publicNetworkAccessForQuery: privateNetworking ? 'Disabled' : 'Enabled'
    features: { disableLocalAuth: true }
  }
}

resource onboarding 'Microsoft.SecurityInsights/onboardingStates@2024-03-01' = {
  name: 'default'
  scope: law
  properties: {}
}

resource alertRules 'Microsoft.SecurityInsights/alertRules@2024-03-01' = [
  for r in rules: if (deployAnalyticsRules) {
    name: 'aisoc-${r.id}'
    scope: law
    kind: 'Scheduled'
    dependsOn: [onboarding]
    properties: {
      displayName: r.name
      enabled: analyticsRulesEnabled
      query: r.query
      queryFrequency: r.frequency
      queryPeriod: r.period
      severity: r.severity
      triggerOperator: 'GreaterThan'
      triggerThreshold: 0
      suppressionDuration: 'PT1H'
      suppressionEnabled: false
      tactics: r.tactics
      techniques: r.parent_techniques
      entityMappings: [
        for e in items(r.entities): {
          entityType: entityTypes[e.value].type
          fieldMappings: [{ identifier: entityTypes[e.value].identifier, columnName: e.key }]
        }
      ]
      incidentConfiguration: {
        createIncident: true
        groupingConfiguration: {
          enabled: true
          lookbackDuration: 'PT24H'
          matchingMethod: 'AnyAlert'
          reopenClosedIncident: false
        }
      }
      eventGroupingSettings: { aggregationKind: 'AlertPerResult' }
    }
  }
]

resource auditDiag 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'diag-audit'
  scope: law
  properties: {
    workspaceId: law.id
    logs: [{ categoryGroup: 'audit', enabled: true }]
  }
}

output id string = law.id
output name string = law.name
