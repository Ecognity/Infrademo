variable "name" { type = string }
variable "location" { type = string }
variable "resource_group_name" { type = string }
variable "tenant_id" { type = string }
variable "tags" { 
  type        = map(string)
  description = "A mapping of tags to assign to the Key Vault resource"
}

