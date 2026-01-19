terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "4.56.0"
    }
  }
}

provider "azurerm" {
  features {

  }
  use_oidc = true

}

module "rg" {
  source   = "../../modules/resource_group"
  name     = var.rg_name
  location = var.location
  tags     = var.tags
}





module "log_analytics" {
  source              = "../../modules/loganylatics"
  name                = var.log_name
  location            = var.location
  resource_group_name = var.rg_name

}

module "app_insights" {
  source              = "../../modules/app_insights"
  name                = var.appi_name
  location            = var.location
  resource_group_name = module.rg.resource_group_name
  workspace_id        = module.log_analytics.id

}

data "azurerm_client_config" "current" {}


module "key_vault" {
  source              = "../../modules/key_vault"
  name                = var.kv_name
  location            = var.location
  resource_group_name = module.rg.resource_group_name
  tenant_id           = data.azurerm_client_config.current.tenant_id
  tags                = var.tags

}

module "app_service" {
  source              = "../../modules/app_service"
  location            = var.location
  resource_group_name = module.rg.resource_group_name


  app_service_plan_name = var.asp_name
  web_app_name          = var.web_name
  sku_name              = var.app_service_sku

  app_insights_connection_string = module.app_insights.connection_string

  enable_staging_slot = true

}




