terraform {
  backend "azurerm" {
    resource_group_name  = "keu-demo-rg"
    storage_account_name = "keudemosto"
    container_name       = "tfstate"
    key                  = "test/terraform.tfstate"
  }
}
