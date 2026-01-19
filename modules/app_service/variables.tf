variable "location" { type = string }
variable "resource_group_name" { type = string }


variable "app_service_plan_name" { type = string }
variable "web_app_name" { type = string }
variable "sku_name" { type = string }

variable "app_insights_connection_string" { type = string }

variable "demo_secret_kv_reference" {
  type    = string
  default = null
}

variable "enable_staging_slot" {
  type        = bool
  default     = false
  description = "Enable staging slot for blue-green deployment"
}
