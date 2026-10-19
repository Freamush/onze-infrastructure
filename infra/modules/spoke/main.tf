resource "azurerm_virtual_network" "vnet" {
  name                = var.name
  address_space       = [var.vnet_cidr]
  location            = var.location
  resource_group_name = var.rg_name
  tags                = var.tags
}
resource "azurerm_subnet" "subnet" {
  name                              = "subnet-${var.name}"
  resource_group_name               = var.rg_name
  virtual_network_name              = azurerm_virtual_network.vnet.name
  address_prefixes                  = [var.subnet_cidr]
  private_endpoint_network_policies = var.private_endpoint_policy
}
resource "azurerm_virtual_network_peering" "hub-to-spoke" {
  name                         = "${var.hub_name}-to-${var.name}"
  resource_group_name          = var.rg_name
  virtual_network_name         = var.hub_name
  remote_virtual_network_id    = azurerm_virtual_network.vnet.id
  allow_forwarded_traffic      = true
  allow_virtual_network_access = true
  allow_gateway_transit        = false
  use_remote_gateways          = false
}

resource "azurerm_virtual_network_peering" "spoke-to-hub" {
  name                         = "${var.name}-to-${var.hub_name}"
  resource_group_name          = var.rg_name
  virtual_network_name         = azurerm_virtual_network.vnet.name
  remote_virtual_network_id    = var.hub_id
  allow_forwarded_traffic      = true
  allow_virtual_network_access = true
  allow_gateway_transit        = false
  use_remote_gateways          = false
}

resource "azurerm_network_security_group" "nsg-spoke" {
  name                = "nsg-${var.name}"
  location            = var.location
  resource_group_name = var.rg_name
  tags                = var.tags
}

resource "azurerm_subnet_network_security_group_association" "subnet-nsg-association" {
  subnet_id                 = azurerm_subnet.subnet.id
  network_security_group_id = azurerm_network_security_group.nsg-spoke.id
}

resource "azurerm_route_table" "route-table" {
  name                = "route-table-${var.name}"
  location            = var.location
  resource_group_name = var.rg_name
  route {
    name                   = "route-via-firewall"
    address_prefix         = var.route_prefix
    next_hop_type          = "VirtualAppliance"
    next_hop_in_ip_address = var.firewall_private_ip
  }
  tags = var.tags
}

resource "azurerm_subnet_route_table_association" "subnet-route-table-association" {
  subnet_id      = azurerm_subnet.subnet.id
  route_table_id = azurerm_route_table.route-table.id
}


resource "azurerm_network_security_rule" "deny-all-other-traffic" {
  name                        = "deny-all-other-traffic"
  priority                    = 4096
  direction                   = "Inbound"
  access                      = "Deny"
  protocol                    = "*"
  source_port_range           = "*"
  destination_port_range      = "*"
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  resource_group_name         = var.rg_name
  network_security_group_name = azurerm_network_security_group.nsg-spoke.name
}


resource "azurerm_private_dns_zone_virtual_network_link" "private-zone-link-vnet-spoke" {
  for_each = var.private_zone_ids

  name                 = "private-zone-link-${var.name}-${each.key}"
  private_dns_zone_id  = each.value
  virtual_network_id   = azurerm_virtual_network.vnet.id
  registration_enabled = false

  tags = var.tags
}