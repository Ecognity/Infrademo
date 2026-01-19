output "web_app_name" { value = azurerm_linux_web_app.web.name }
output "web_app_url" { value = "https://${azurerm_linux_web_app.web.default_hostname}" }

output "webapp_principal_id" {
  value = azurerm_linux_web_app.web.identity[0].principal_id
}

output "plan_id" { value = azurerm_service_plan.plan.id }

output "staging_slot_name" {
  value = var.enable_staging_slot ? azurerm_linux_web_app_slot.staging[0].name : null
}

output "staging_slot_url" {
  value = var.enable_staging_slot ? "https://${azurerm_linux_web_app_slot.staging[0].default_hostname}" : null
}
