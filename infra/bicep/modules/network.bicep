// Optional private networking: Azure Monitor Private Link Scope in private-only mode, a private
// endpoint in its own subnet (with an NSG) and the privatelink DNS zones linked to the VNet.
param suffix string
param location string
param tags object
param workspaceId string
param vnetAddressSpace string

var zones = [
  'privatelink.monitor.azure.com'
  'privatelink.oms.opinsights.azure.com'
  'privatelink.ods.opinsights.azure.com'
  'privatelink.agentsvc.azure-automation.net'
  'privatelink.blob.${az.environment().suffixes.storage}'
]

resource nsg 'Microsoft.Network/networkSecurityGroups@2024-05-01' = {
  name: 'nsg-aisoc-pe-${suffix}'
  location: location
  tags: tags
}

resource vnet 'Microsoft.Network/virtualNetworks@2024-05-01' = {
  name: 'vnet-aisoc-${suffix}'
  location: location
  tags: tags
  properties: {
    addressSpace: { addressPrefixes: [vnetAddressSpace] }
    subnets: [
      {
        name: 'snet-private-endpoints'
        properties: {
          addressPrefix: cidrSubnet(vnetAddressSpace, 26, 0)
          privateEndpointNetworkPolicies: 'Enabled'
          networkSecurityGroup: { id: nsg.id }
        }
      }
    ]
  }
}

resource ampls 'Microsoft.Insights/privateLinkScopes@2021-07-01-preview' = {
  name: 'ampls-aisoc-${suffix}'
  location: 'global'
  tags: tags
  properties: {
    accessModeSettings: { ingestionAccessMode: 'PrivateOnly', queryAccessMode: 'PrivateOnly' }
  }
}

resource scoped 'Microsoft.Insights/privateLinkScopes/scopedResources@2021-07-01-preview' = {
  parent: ampls
  name: 'ampls-law'
  properties: { linkedResourceId: workspaceId }
}

resource dns 'Microsoft.Network/privateDnsZones@2024-06-01' = [
  for z in zones: {
    name: z
    location: 'global'
    tags: tags
  }
]

resource links 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2024-06-01' = [
  for (z, i) in zones: {
    parent: dns[i]
    name: 'link-${replace(z, '.', '-')}'
    location: 'global'
    tags: tags
    properties: { registrationEnabled: false, virtualNetwork: { id: vnet.id } }
  }
]

resource pe 'Microsoft.Network/privateEndpoints@2024-05-01' = {
  name: 'pe-ampls-${suffix}'
  location: location
  tags: tags
  dependsOn: [scoped]
  properties: {
    subnet: { id: vnet.properties.subnets[0].id }
    privateLinkServiceConnections: [
      {
        name: 'ampls'
        properties: { privateLinkServiceId: ampls.id, groupIds: ['azuremonitor'] }
      }
    ]
  }
}

resource zoneGroup 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2024-05-01' = {
  parent: pe
  name: 'ampls'
  properties: {
    privateDnsZoneConfigs: [for (z, i) in zones: { name: replace(z, '.', '-'), properties: { privateDnsZoneId: dns[i].id } }]
  }
}
