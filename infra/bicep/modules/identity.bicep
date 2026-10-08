// Two user-assigned identities with least privilege at workspace scope:
//   playbook -> Microsoft Sentinel Responder (read incidents, comment, change status)
//   agent    -> Microsoft Sentinel Reader    (query for investigation)
// No Microsoft Graph or Defender permission is granted here; containment is a separate,
// human-approved executor that this template does not create.
param suffix string
param location string
param tags object
param workspaceName string

// Built-in role definition IDs (public, identical in every tenant).
var sentinelResponder = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '3e150937-b8fe-4cfb-8069-0eaf05ecd056')
var sentinelReader = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '8d289c81-5878-46d4-8554-54e1e3d8b5cb')

resource law 'Microsoft.OperationalInsights/workspaces@2023-09-01' existing = {
  name: workspaceName
}

resource playbookId 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: 'id-aisoc-playbook-${suffix}'
  location: location
  tags: tags
}

resource agentId 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: 'id-aisoc-agent-${suffix}'
  location: location
  tags: tags
}

resource playbookResponder 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(law.id, playbookId.id, sentinelResponder)
  scope: law
  properties: {
    principalId: playbookId.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: sentinelResponder
  }
}

resource agentReader 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(law.id, agentId.id, sentinelReader)
  scope: law
  properties: {
    principalId: agentId.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: sentinelReader
  }
}

output playbookIdentityId string = playbookId.id
output agentClientId string = agentId.properties.clientId
