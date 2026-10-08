terraform {
  required_version = ">= 1.9.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 5.8"
    }
    # Only for the Logic App's Microsoft Sentinel API connection with managed-identity auth
    # (parameterValueType "Alternative"), which azurerm_api_connection cannot express.
    azapi = {
      source  = "Azure/azapi"
      version = "~> 2.5"
    }
  }
}
