resource "azurerm_storage_account" "this" {
  name                     = var.name
  resource_group_name      = var.resource_group_name
  location                 = var.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  allow_nested_items_to_be_public = true   # ❌ Checkov will flag this
  min_tls_version                 = "TLS1_0" # ❌ Weak TLS
}
