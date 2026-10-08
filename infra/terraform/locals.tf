locals {
  short_location = {
    eastus2    = "eus2"
    westus2    = "wus2"
    westeurope = "weu"
  }
  suffix = "${var.tenant_slug}-${var.environment}-${local.short_location[var.location]}"

  tags = merge({
    workload    = "aisoc"
    environment = var.environment
    tenant      = var.tenant_slug
    managed_by  = "terraform"
    data        = "security-telemetry"
  }, var.tags)

  # The same rules the offline simulation runs, with their KQL embedded (built by `aisoc rules-json`).
  rules = { for r in jsondecode(file("${path.module}/../../detections/rules.json")).rules : r.id => r }

  entity_type = {
    account = { type = "Account", identifier = "FullName" }
    host    = { type = "Host", identifier = "HostName" }
    ip      = { type = "IP", identifier = "Address" }
    url     = { type = "URL", identifier = "Url" }
  }

  severity = { Low = "Low", Medium = "Medium", High = "High" }

  private_dns_zones = toset([
    "privatelink.monitor.azure.com",
    "privatelink.oms.opinsights.azure.com",
    "privatelink.ods.opinsights.azure.com",
    "privatelink.agentsvc.azure-automation.net",
    "privatelink.blob.core.windows.net",
  ])
}
