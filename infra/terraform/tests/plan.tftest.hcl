# Offline plan tests: mocked providers, no Azure credentials, nothing created.
#   terraform init -backend=false && terraform test
mock_provider "azurerm" {
  mock_data "azurerm_client_config" {
    defaults = {
      tenant_id       = "00000000-0000-0000-0000-000000000001"
      subscription_id = "00000000-0000-0000-0000-000000000002"
      object_id       = "00000000-0000-0000-0000-000000000003"
    }
  }
  mock_data "azurerm_subscription" {
    defaults = {
      id              = "/subscriptions/00000000-0000-0000-0000-000000000002"
      subscription_id = "00000000-0000-0000-0000-000000000002"
    }
  }
}

mock_provider "azapi" {}

# Values that are only known after apply, made available at plan time for the assertions.
override_resource {
  target          = azurerm_user_assigned_identity.playbook
  override_during = plan
  values = {
    id           = "/subscriptions/00000000-0000-0000-0000-000000000002/resourceGroups/rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-aisoc-playbook"
    principal_id = "00000000-0000-0000-0000-000000000004"
  }
}

override_resource {
  target          = azapi_resource.sentinel_connection
  override_during = plan
  values = {
    id = "/subscriptions/00000000-0000-0000-0000-000000000002/resourceGroups/rg/providers/Microsoft.Web/connections/azuresentinel"
  }
}

run "dev_defaults" {
  command = plan

  variables {
    environment = "dev"
  }

  assert {
    condition     = azurerm_resource_group.this.name == "rg-aisoc-brightwater-dev-eus2-001"
    error_message = "resource group follows the CAF naming pattern and names the customer tenant"
  }

  assert {
    condition     = azurerm_log_analytics_workspace.this.retention_in_days == 90 && azurerm_log_analytics_workspace.this.daily_quota_gb == 1
    error_message = "90-day retention (included with Sentinel) and a 1 GB daily cap"
  }

  assert {
    condition     = !azurerm_log_analytics_workspace.this.local_authentication_enabled
    error_message = "workspace accepts Entra ID auth only"
  }

  assert {
    condition     = azurerm_log_analytics_workspace.this.internet_ingestion_enabled && azurerm_log_analytics_workspace.this.internet_query_enabled
    error_message = "public access stays on when private networking is off"
  }

  assert {
    condition     = length(azurerm_sentinel_alert_rule_scheduled.rule) == 0
    error_message = "analytics rules are opt-in"
  }

  assert {
    condition     = azurerm_role_assignment.playbook_responder.role_definition_name == "Microsoft Sentinel Responder" && azurerm_role_assignment.agent_reader.role_definition_name == "Microsoft Sentinel Reader"
    error_message = "playbook can manage incidents; agent can only read"
  }

  assert {
    condition     = length(azurerm_logic_app_action_custom.forward_to_agent) == 0 && length(azurerm_sentinel_automation_rule.triage) == 0
    error_message = "no HTTP action without an agent endpoint; no automation rule unless asked"
  }

  assert {
    condition     = jsondecode(azurerm_logic_app_trigger_custom.incident_created.body).inputs.path == "/incident-creation"
    error_message = "playbook triggers on incident creation"
  }

  assert {
    condition     = jsondecode(azurerm_logic_app_workflow.playbook.parameters["$connections"]).azuresentinel.connectionProperties.authentication.type == "ManagedServiceIdentity"
    error_message = "the Sentinel connection authenticates with the managed identity"
  }

  assert {
    condition     = azapi_resource.sentinel_connection.body.properties.parameterValueType == "Alternative"
    error_message = "API connection is the managed-identity kind"
  }

  assert {
    condition     = length(azurerm_virtual_network.this) == 0 && length(azurerm_private_dns_zone.this) == 0
    error_message = "no network resources when private networking is off"
  }

  assert {
    condition     = one(azurerm_monitor_diagnostic_setting.playbook.enabled_log).category == "WorkflowRuntime" && one(azurerm_monitor_diagnostic_setting.workspace_audit.enabled_log).category_group == "audit"
    error_message = "playbook runs and workspace queries are logged"
  }
}

run "analytics_rules" {
  command = plan

  variables {
    environment            = "dev"
    deploy_analytics_rules = true
  }

  assert {
    condition     = length(azurerm_sentinel_alert_rule_scheduled.rule) == 12
    error_message = "one scheduled rule per detections/rules.json entry"
  }

  assert {
    condition     = alltrue([for r in azurerm_sentinel_alert_rule_scheduled.rule : !r.enabled])
    error_message = "rules start disabled until their schema mapping is checked"
  }

  assert {
    condition     = toset(azurerm_sentinel_alert_rule_scheduled.rule["password-spray"].techniques) == toset(["T1110"]) && toset(azurerm_sentinel_alert_rule_scheduled.rule["password-spray"].tactics) == toset(["CredentialAccess"])
    error_message = "ATT&CK tactics and parent techniques are carried over"
  }

  assert {
    condition     = azurerm_sentinel_alert_rule_scheduled.rule["mass-download"].query_frequency == "PT1H" && azurerm_sentinel_alert_rule_scheduled.rule["mass-download"].query_period == "P1D"
    error_message = "schedules come from rules.yaml"
  }

  assert {
    condition     = length(azurerm_sentinel_alert_rule_scheduled.rule["ti-c2-connection"].entity_mapping) == 2
    error_message = "entity mappings come from rules.yaml"
  }
}

run "private_networking_and_agent_endpoint" {
  command = plan

  variables {
    environment            = "prod"
    private_networking     = true
    agent_endpoint         = "https://agent.aisoc.example/triage"
    enable_automation_rule = true
  }

  assert {
    condition     = !azurerm_log_analytics_workspace.this.internet_ingestion_enabled && !azurerm_log_analytics_workspace.this.internet_query_enabled
    error_message = "private mode closes public ingestion and query"
  }

  assert {
    condition     = azurerm_monitor_private_link_scope.this[0].ingestion_access_mode == "PrivateOnly" && azurerm_monitor_private_link_scope.this[0].query_access_mode == "PrivateOnly"
    error_message = "AMPLS is private-only"
  }

  assert {
    condition     = length(azurerm_private_dns_zone.this) == 5 && length(azurerm_private_dns_zone_virtual_network_link.this) == 5
    error_message = "five privatelink zones, each linked to the VNet"
  }

  assert {
    condition     = jsondecode(azurerm_logic_app_action_custom.forward_to_agent[0].body).inputs.authentication.type == "ManagedServiceIdentity"
    error_message = "the agent call uses a managed-identity token, not a key"
  }

  assert {
    condition     = length(azurerm_sentinel_automation_rule.triage) == 1 && azurerm_sentinel_automation_rule.triage[0].triggers_when == "Created"
    error_message = "automation rule runs the playbook on new incidents"
  }
}

run "rejects_plain_http_endpoint" {
  command = plan

  variables {
    environment    = "dev"
    agent_endpoint = "http://agent.aisoc.example"
  }

  expect_failures = [var.agent_endpoint]
}
