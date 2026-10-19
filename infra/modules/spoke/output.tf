output "nsg_name" {
  value = azurerm_network_security_group.nsg-spoke.name
}
output "subnet" {
  value = azurerm_subnet.subnet
}
output "vnet_name" {
  value = azurerm_virtual_network.vnet.name
}
output "vnet_id" {
  value = azurerm_virtual_network.vnet.id
}

output "private_link_id" {
  value = { for k, v in azurerm_private_dns_zone_virtual_network_link.private-zone-link-vnet-spoke : k => v.id }
}
