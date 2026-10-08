# Optional private networking (var.private_networking): agents and collectors reach the workspace
# only through an Azure Monitor Private Link Scope in private-only mode, and the workspace refuses
# public ingestion and queries (see azurerm_log_analytics_workspace.this).
resource "azurerm_virtual_network" "this" {
  count               = var.private_networking ? 1 : 0
  name                = "vnet-aisoc-${local.suffix}"
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  address_space       = [var.vnet_address_space]
  tags                = local.tags
}

resource "azurerm_subnet" "private_endpoints" {
  count                = var.private_networking ? 1 : 0
  name                 = "snet-private-endpoints"
  resource_group_name  = azurerm_resource_group.this.name
  virtual_network_name = azurerm_virtual_network.this[0].name
  address_prefixes     = [cidrsubnet(var.vnet_address_space, 2, 0)]

  private_endpoint_network_policies = "Enabled"
}

resource "azurerm_monitor_private_link_scope" "this" {
  count                 = var.private_networking ? 1 : 0
  name                  = "ampls-aisoc-${local.suffix}"
  resource_group_name   = azurerm_resource_group.this.name
  ingestion_access_mode = "PrivateOnly"
  query_access_mode     = "PrivateOnly"
  tags                  = local.tags
}

resource "azurerm_monitor_private_link_scoped_service" "workspace" {
  count               = var.private_networking ? 1 : 0
  name                = "ampls-law"
  resource_group_name = azurerm_resource_group.this.name
  scope_name          = azurerm_monitor_private_link_scope.this[0].name
  linked_resource_id  = azurerm_log_analytics_workspace.this.id
}

resource "azurerm_private_dns_zone" "this" {
  for_each            = var.private_networking ? local.private_dns_zones : toset([])
  name                = each.value
  resource_group_name = azurerm_resource_group.this.name
  tags                = local.tags
}

resource "azurerm_private_dns_zone_virtual_network_link" "this" {
  for_each              = azurerm_private_dns_zone.this
  name                  = "link-${replace(each.key, ".", "-")}"
  resource_group_name   = azurerm_resource_group.this.name
  private_dns_zone_name = each.value.name
  virtual_network_id    = azurerm_virtual_network.this[0].id
  tags                  = local.tags
}

resource "azurerm_private_endpoint" "ampls" {
  count               = var.private_networking ? 1 : 0
  name                = "pe-ampls-${local.suffix}"
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  subnet_id           = azurerm_subnet.private_endpoints[0].id
  tags                = local.tags

  private_service_connection {
    name                           = "ampls"
    private_connection_resource_id = azurerm_monitor_private_link_scope.this[0].id
    subresource_names              = ["azuremonitor"]
    is_manual_connection           = false
  }

  private_dns_zone_group {
    name                 = "ampls"
    private_dns_zone_ids = [for z in azurerm_private_dns_zone.this : z.id]
  }

  depends_on = [azurerm_monitor_private_link_scoped_service.workspace]
}

# NSG on the private-endpoint subnet (no rules beyond the platform defaults; private endpoints
# honour NSG rules when subnet network policies are enabled).
resource "azurerm_network_security_group" "private_endpoints" {
  count               = var.private_networking ? 1 : 0
  name                = "nsg-aisoc-pe-${local.suffix}"
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  tags                = local.tags
}

resource "azurerm_subnet_network_security_group_association" "private_endpoints" {
  count                     = var.private_networking ? 1 : 0
  subnet_id                 = azurerm_subnet.private_endpoints[0].id
  network_security_group_id = azurerm_network_security_group.private_endpoints[0].id
}
