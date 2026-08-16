output "subscription_id" {
  value = var.subscription_id
}

output "resource_group" {
  value = azurerm_resource_group.main.name
}

output "virtual_network" {
  value = azurerm_virtual_network.main.name
}

output "nsg_ids" {
  description = "ARM IDs of all NSGs created by this scaffold"
  value = {
    violation = azurerm_network_security_group.violation.id
    anyany    = azurerm_network_security_group.anyany.id
    weird     = azurerm_network_security_group.weird.id
    flowlog   = azurerm_network_security_group.flowlog_nsg.id
  }
}
