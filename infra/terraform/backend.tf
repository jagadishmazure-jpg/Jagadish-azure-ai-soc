# Remote state in Azure Storage with Entra ID auth. Values are passed at init time
# (see .github/scripts/deploy.sh); CI validation uses -backend=false.
terraform {
  backend "azurerm" {
    use_azuread_auth = true
  }
}
