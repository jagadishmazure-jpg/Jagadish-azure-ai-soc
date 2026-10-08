data "azurerm_client_config" "current" {}

data "azurerm_subscription" "current" {}

resource "azurerm_resource_group" "this" {
  name     = "rg-aisoc-${local.suffix}-001"
  location = var.location
  tags     = local.tags
}

# ---------------------------------------------------------------------------------------------
# Log Analytics + Microsoft Sentinel
# ---------------------------------------------------------------------------------------------
resource "azurerm_log_analytics_workspace" "this" {
  name                         = "law-aisoc-${local.suffix}"
  location                     = azurerm_resource_group.this.location
  resource_group_name          = azurerm_resource_group.this.name
  sku                          = "PerGB2018"
  retention_in_days            = var.retention_in_days
  daily_quota_gb               = var.daily_quota_gb
  internet_ingestion_enabled   = !var.private_networking
  internet_query_enabled       = !var.private_networking
  local_authentication_enabled = false
  tags                         = local.tags
}

resource "azurerm_sentinel_log_analytics_workspace_onboarding" "this" {
  workspace_id = azurerm_log_analytics_workspace.this.id
}

# One scheduled analytics rule per entry in detections/rules.json: the same KQL the offline
# simulation runs. ATT&CK techniques are sent as parent IDs (the API's techniques field).
resource "azurerm_sentinel_alert_rule_scheduled" "rule" {
  for_each = var.deploy_analytics_rules ? local.rules : {}

  name                       = "aisoc-${each.key}"
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.this.workspace_id
  display_name               = each.value.name
  severity                   = local.severity[each.value.severity]
  query                      = each.value.query
  query_frequency            = each.value.frequency
  query_period               = each.value.period
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  tactics                    = each.value.tactics
  techniques                 = each.value.parent_techniques
  enabled                    = var.analytics_rules_enabled

  dynamic "entity_mapping" {
    for_each = each.value.entities
    content {
      entity_type = local.entity_type[entity_mapping.value].type
      field_mapping {
        identifier  = local.entity_type[entity_mapping.value].identifier
        column_name = entity_mapping.key
      }
    }
  }

  incident {
    create_incident_enabled = true
    grouping {
      enabled                 = true
      lookback_duration       = "PT24H"
      reopen_closed_incidents = false
      entity_matching_method  = "AnyAlert"
    }
  }

  event_grouping {
    aggregation_method = "AlertPerResult"
  }
}

# ---------------------------------------------------------------------------------------------
# Identities: least privilege, workspace scope only
#   playbook -> Microsoft Sentinel Responder (read incidents, add comments, change status)
#   agent    -> Microsoft Sentinel Reader    (query the workspace for investigation)
# Neither identity is granted any Microsoft Graph or Defender permission: containment actions
# stay with a separate, human-approved executor that this stack does not create.
# ---------------------------------------------------------------------------------------------
resource "azurerm_user_assigned_identity" "playbook" {
  name                = "id-aisoc-playbook-${local.suffix}"
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  tags                = local.tags
}

resource "azurerm_user_assigned_identity" "agent" {
  name                = "id-aisoc-agent-${local.suffix}"
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  tags                = local.tags
}

resource "azurerm_role_assignment" "playbook_responder" {
  scope                = azurerm_log_analytics_workspace.this.id
  role_definition_name = "Microsoft Sentinel Responder"
  principal_id         = azurerm_user_assigned_identity.playbook.principal_id
  principal_type       = "ServicePrincipal"
}

resource "azurerm_role_assignment" "agent_reader" {
  scope                = azurerm_log_analytics_workspace.this.id
  role_definition_name = "Microsoft Sentinel Reader"
  principal_id         = azurerm_user_assigned_identity.agent.principal_id
  principal_type       = "ServicePrincipal"
}

# ---------------------------------------------------------------------------------------------
# Playbook: Logic App (consumption) triggered by a new Sentinel incident. It forwards the incident
# to the triage agent with a managed-identity token. It never contains a containment action.
# ---------------------------------------------------------------------------------------------
resource "azapi_resource" "sentinel_connection" {
  type                      = "Microsoft.Web/connections@2016-06-01"
  name                      = "azuresentinel-${local.suffix}"
  parent_id                 = azurerm_resource_group.this.id
  location                  = azurerm_resource_group.this.location
  schema_validation_enabled = false
  tags                      = local.tags
  body = {
    kind = "V1"
    properties = {
      displayName        = "Microsoft Sentinel (managed identity)"
      parameterValueType = "Alternative"
      api = {
        id = "${data.azurerm_subscription.current.id}/providers/Microsoft.Web/locations/${azurerm_resource_group.this.location}/managedApis/azuresentinel"
      }
    }
  }
}

resource "azurerm_logic_app_workflow" "playbook" {
  name                = "logic-aisoc-triage-${local.suffix}"
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  tags                = local.tags

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.playbook.id]
  }

  workflow_parameters = {
    "$connections" = jsonencode({ type = "Object", defaultValue = {} })
  }

  parameters = {
    "$connections" = jsonencode({
      azuresentinel = {
        connectionId   = azapi_resource.sentinel_connection.id
        connectionName = azapi_resource.sentinel_connection.name
        id             = "${data.azurerm_subscription.current.id}/providers/Microsoft.Web/locations/${azurerm_resource_group.this.location}/managedApis/azuresentinel"
        connectionProperties = {
          authentication = {
            type     = "ManagedServiceIdentity"
            identity = azurerm_user_assigned_identity.playbook.id
          }
        }
      }
    })
  }
}

resource "azurerm_logic_app_trigger_custom" "incident_created" {
  name         = "Microsoft_Sentinel_incident"
  logic_app_id = azurerm_logic_app_workflow.playbook.id
  body = jsonencode({
    type = "ApiConnectionWebhook"
    inputs = {
      body = { callback_url = "@{listCallbackUrl()}" }
      host = { connection = { name = "@parameters('$connections')['azuresentinel']['connectionId']" } }
      path = "/incident-creation"
    }
  })
}

resource "azurerm_logic_app_action_custom" "forward_to_agent" {
  count        = var.agent_endpoint == "" ? 0 : 1
  name         = "Forward_to_triage_agent"
  logic_app_id = azurerm_logic_app_workflow.playbook.id
  body = jsonencode({
    type     = "Http"
    runAfter = {}
    inputs = {
      method = "POST"
      uri    = var.agent_endpoint
      body = {
        incidentArmId = "@triggerBody()?['object']?['id']"
        tenant        = var.tenant_slug
        workspace     = azurerm_log_analytics_workspace.this.name
      }
      authentication = {
        type     = "ManagedServiceIdentity"
        identity = azurerm_user_assigned_identity.playbook.id
        audience = var.agent_audience
      }
    }
  })
}

resource "azurerm_sentinel_automation_rule" "triage" {
  count                      = var.enable_automation_rule ? 1 : 0
  name                       = uuidv5("url", "https://aisoc.example/automation/${local.suffix}")
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.this.workspace_id
  display_name               = "Send new incidents to the AI triage agent"
  order                      = 1
  triggers_on                = "Incidents"
  triggers_when              = "Created"

  action_playbook {
    logic_app_id = azurerm_logic_app_workflow.playbook.id
    order        = 1
    tenant_id    = data.azurerm_client_config.current.tenant_id
  }
}

# ---------------------------------------------------------------------------------------------
# Diagnostic settings: workspace query audit and playbook run history into the workspace
# ---------------------------------------------------------------------------------------------
resource "azurerm_monitor_diagnostic_setting" "workspace_audit" {
  name                       = "diag-audit"
  target_resource_id         = azurerm_log_analytics_workspace.this.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.this.id

  enabled_log {
    category_group = "audit"
  }
}

resource "azurerm_monitor_diagnostic_setting" "playbook" {
  name                       = "diag-runtime"
  target_resource_id         = azurerm_logic_app_workflow.playbook.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.this.id

  enabled_log {
    category = "WorkflowRuntime"
  }
}
