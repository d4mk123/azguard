variable "subscription_id" {
  description = "Azure subscription ID to provision into"
  type        = string
}

variable "location" {
  description = "Azure region for all resources"
  type        = string
  default     = "eastus"
}

variable "prefix" {
  description = "Prefix applied to resource names"
  type        = string
  default     = "azguard"
}
