variable "environment" {
  description = "dev or prod."
  type        = string
  validation {
    condition     = contains(["dev", "prod"], var.environment)
    error_message = "environment must be dev or prod."
  }
}

variable "location" {
  description = "Azure region."
  type        = string
  default     = "eastus2"
  validation {
    condition     = contains(["eastus2", "westus2", "westeurope"], var.location)
    error_message = "location must be one of the regions in locals.short_location."
  }
}

variable "tenant_slug" {
  description = "Short name of the customer tenant this workspace serves (one workspace per customer tenant)."
  type        = string
  default     = "brightwater"
  validation {
    condition     = can(regex("^[a-z][a-z0-9]{2,15}$", var.tenant_slug))
    error_message = "tenant_slug must be 3-16 lowercase letters or digits."
  }
}

variable "retention_in_days" {
  description = "Log Analytics retention. Sentinel includes 90 days at no retention charge."
  type        = number
  default     = 90
}

variable "daily_quota_gb" {
  description = "Daily ingestion cap in GB (-1 for none). A small cap keeps a demo workspace cheap."
  type        = number
  default     = 1
}

variable "deploy_analytics_rules" {
  description = "Create the scheduled analytics rules from detections/rules.json. Off by default: the queries target the repository's simplified schema and need the column mapping in docs/infra/sentinel-workspace.md first."
  type        = bool
  default     = false
}

variable "analytics_rules_enabled" {
  description = "When the rules are created, whether they start enabled."
  type        = bool
  default     = false
}

variable "agent_endpoint" {
  description = "HTTPS endpoint of the triage agent the playbook forwards new incidents to. Empty: the playbook is created without the HTTP action."
  type        = string
  default     = ""
  validation {
    condition     = var.agent_endpoint == "" || startswith(var.agent_endpoint, "https://")
    error_message = "agent_endpoint must be empty or an https:// URL."
  }
}

variable "agent_audience" {
  description = "Entra ID application ID URI the playbook requests a token for when calling the agent endpoint."
  type        = string
  default     = "api://aisoc-agent"
}

variable "enable_automation_rule" {
  description = "Create a Sentinel automation rule that runs the playbook on every new incident. Needs the Microsoft Sentinel Automation Contributor role for the Sentinel service principal on the resource group (see docs/infra/playbook.md)."
  type        = bool
  default     = false
}

variable "private_networking" {
  description = "Private-only ingestion and query through an Azure Monitor Private Link Scope, a private endpoint and privatelink DNS zones."
  type        = bool
  default     = false
}

variable "vnet_address_space" {
  description = "Address space for the private networking VNet."
  type        = string
  default     = "10.40.0.0/24"
}

variable "tags" {
  description = "Extra tags."
  type        = map(string)
  default     = {}
}
