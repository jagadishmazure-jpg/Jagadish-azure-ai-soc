// Logic App (consumption) playbook: triggered by a new Sentinel incident, forwards it to the triage
// agent with a managed-identity token. It never contains a containment action.
param suffix string
param location string
param tags object
param tenantSlug string
param workspaceName string
param playbookIdentityId string
param agentEndpoint string
param agentAudience string
param enableAutomationRule bool

var managedApiId = subscriptionResourceId('Microsoft.Web/locations/managedApis', location, 'azuresentinel')

resource law 'Microsoft.OperationalInsights/workspaces@2023-09-01' existing = {
  name: workspaceName
}

resource connection 'Microsoft.Web/connections@2016-06-01' = {
  name: 'azuresentinel-${suffix}'
  location: location
  tags: tags
  #disable-next-line BCP187
  kind: 'V1'
  properties: {
    displayName: 'Microsoft Sentinel (managed identity)'
    #disable-next-line BCP037
    parameterValueType: 'Alternative'
    api: { id: managedApiId }
  }
}

var forwardAction = {
  Forward_to_triage_agent: {
    type: 'Http'
    runAfter: {}
    inputs: {
      method: 'POST'
      uri: agentEndpoint
      body: {
        incidentArmId: '@triggerBody()?[\'object\']?[\'id\']'
        tenant: tenantSlug
        workspace: workspaceName
      }
      authentication: {
        type: 'ManagedServiceIdentity'
        identity: playbookIdentityId
        audience: agentAudience
      }
    }
  }
}

resource playbook 'Microsoft.Logic/workflows@2019-05-01' = {
  name: 'logic-aisoc-triage-${suffix}'
  location: location
  tags: tags
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: { '${playbookIdentityId}': {} }
  }
  properties: {
    state: 'Enabled'
    definition: {
      '$schema': 'https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#'
      contentVersion: '1.0.0.0'
      parameters: {
        '$connections': { type: 'Object', defaultValue: {} }
      }
      triggers: {
        Microsoft_Sentinel_incident: {
          type: 'ApiConnectionWebhook'
          inputs: {
            body: { callback_url: '@{listCallbackUrl()}' }
            host: { connection: { name: '@parameters(\'$connections\')[\'azuresentinel\'][\'connectionId\']' } }
            path: '/incident-creation'
          }
        }
      }
      actions: empty(agentEndpoint) ? {} : forwardAction
    }
    parameters: {
      '$connections': {
        value: {
          azuresentinel: {
            connectionId: connection.id
            connectionName: connection.name
            id: managedApiId
            connectionProperties: {
              authentication: { type: 'ManagedServiceIdentity', identity: playbookIdentityId }
            }
          }
        }
      }
    }
  }
}

resource runtimeDiag 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'diag-runtime'
  scope: playbook
  properties: {
    workspaceId: law.id
    logs: [{ category: 'WorkflowRuntime', enabled: true }]
  }
}

resource automationRule 'Microsoft.SecurityInsights/automationRules@2024-03-01' = if (enableAutomationRule) {
  name: guid(law.id, 'aisoc-triage-automation')
  scope: law
  properties: {
    displayName: 'Send new incidents to the AI triage agent'
    order: 1
    triggeringLogic: { isEnabled: true, triggersOn: 'Incidents', triggersWhen: 'Created' }
    actions: [
      {
        actionType: 'RunPlaybook'
        order: 1
        actionConfiguration: { logicAppResourceId: playbook.id, tenantId: subscription().tenantId }
      }
    ]
  }
}

output id string = playbook.id
