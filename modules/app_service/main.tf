resource "azurerm_service_plan" "plan" {
  name                = var.app_service_plan_name
  location            = var.location
  resource_group_name = var.resource_group_name

  os_type  = "Linux"
  sku_name = var.sku_name


}

resource "azurerm_linux_web_app" "web" {
  name                = var.web_app_name
  location            = var.location
  resource_group_name = var.resource_group_name
  service_plan_id     = azurerm_service_plan.plan.id

  https_only = true

  identity {
    type = "SystemAssigned"
  }

  site_config {
    always_on           = true
    ftps_state          = "Disabled"
    minimum_tls_version = "1.2"

    application_stack {
      dotnet_version = "8.0"
    }
  }

  app_settings = merge(
    {
      "ASPNETCORE_ENVIRONMENT"                = "Production"
      "APPLICATIONINSIGHTS_CONNECTION_STRING" = var.app_insights_connection_string
    },
    var.demo_secret_kv_reference == null ? {} : {
      "DEMO_SECRET" = var.demo_secret_kv_reference
    }
  )


}

resource "azurerm_linux_web_app_slot" "staging" {
  count              = var.enable_staging_slot ? 1 : 0
  name               = "staging"
  app_service_id     = azurerm_linux_web_app.web.id

  https_only = true

  identity {
    type = "SystemAssigned"
  }

  site_config {
    always_on           = true
    ftps_state          = "Disabled"
    minimum_tls_version = "1.2"

    application_stack {
      dotnet_version = "8.0"
    }
  }

  app_settings = merge(
    {
      "ASPNETCORE_ENVIRONMENT"                = "Staging"
      "APPLICATIONINSIGHTS_CONNECTION_STRING" = var.app_insights_connection_string
    },
    var.demo_secret_kv_reference == null ? {} : {
      "DEMO_SECRET" = var.demo_secret_kv_reference
    }
  )
}
