resource "azurerm_network_security_rule" "allow-ssh-from-bastion-to-spoke1" {
  name                        = "allow-ssh-from-bastion"
  priority                    = 200
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "22"
  source_address_prefix       = azurerm_subnet.bastion-subnet.address_prefixes[0]
  destination_address_prefix  = module.spoke1.subnet.address_prefixes[0]
  resource_group_name         = azurerm_resource_group.Secure-Landing-Zone-IaC.name
  network_security_group_name = module.spoke1.nsg_name
}

resource "azurerm_network_security_rule" "allow-443-to-spoke2" {
  name                        = "allow-443-from-spoke1-to-spoke2"
  priority                    = 200
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "443"
  source_address_prefix       = module.spoke1.subnet.address_prefixes[0]
  destination_address_prefix  = module.spoke2.subnet.address_prefixes[0]
  resource_group_name         = azurerm_resource_group.Secure-Landing-Zone-IaC.name
  network_security_group_name = module.spoke2.nsg_name
}

resource "azurerm_network_security_rule" "allow-rgp-from-bastion-to-spoke3" {
  name                        = "allow-rdp-from-bastion"
  priority                    = 200
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "3389"
  source_address_prefix       = azurerm_subnet.bastion-subnet.address_prefixes[0]
  destination_address_prefix  = module.spoke3.subnet.address_prefixes[0]
  resource_group_name         = azurerm_resource_group.Secure-Landing-Zone-IaC.name
  network_security_group_name = module.spoke3.nsg_name
}

resource "azurerm_network_security_rule" "allow-from-spks-to-spk4" {
  name                        = "allow-443-from-spoke1-to-spoke4"
  priority                    = 200
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "443"
  source_address_prefixes     = [module.spoke1.subnet.address_prefixes[0], module.spoke3.subnet.address_prefixes[0]]
  destination_address_prefix  = module.spoke4.subnet.address_prefixes[0]
  resource_group_name         = azurerm_resource_group.Secure-Landing-Zone-IaC.name
  network_security_group_name = module.spoke4.nsg_name
}