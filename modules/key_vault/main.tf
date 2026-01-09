resource "azurerm_key_vault" "this" {
  name                = var.name
  location            = var.location
  resource_group_name = var.resource_group_name
  tenant_id           = var.tenant_id
  sku_name            = "standard"

  # Security
  purge_protection_enabled      = true
  soft_delete_retention_days    = 14
  rbac_authorization_enabled    = true
  public_network_access_enabled = true
  network_acls {
    default_action = "Deny"
    bypass         = "AzureServices"
 }

  tags = var.tags

}
