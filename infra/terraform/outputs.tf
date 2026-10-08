output "AZURE_RESOURCE_GROUP" {
  value = azurerm_resource_group.this.name
}

output "LOG_ANALYTICS_WORKSPACE_NAME" {
  value = azurerm_log_analytics_workspace.this.name
}

output "LOG_ANALYTICS_WORKSPACE_ID" {
  value = azurerm_log_analytics_workspace.this.id
}

output "PLAYBOOK_ID" {
  value = azurerm_logic_app_workflow.playbook.id
}

output "AGENT_IDENTITY_CLIENT_ID" {
  description = "Client ID the triage agent uses (DefaultAzureCredential with AZURE_CLIENT_ID) to query the workspace."
  value       = azurerm_user_assigned_identity.agent.client_id
}

output "ANALYTICS_RULES" {
  value = sort([for r in azurerm_sentinel_alert_rule_scheduled.rule : r.name])
}
