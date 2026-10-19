resource "azurerm_virtual_network" "vnet-lz-hub" {
  name                = "vnet-lz-hub"
  address_space       = [var.HUB-IP-CIDR]
  location            = azurerm_resource_group.Secure-Landing-Zone-IaC.location
  resource_group_name = azurerm_resource_group.Secure-Landing-Zone-IaC.name
  tags                = local.tags
}

resource "azurerm_subnet" "subnet1" {
  name                 = "snet-hub-shared"
  resource_group_name  = azurerm_resource_group.Secure-Landing-Zone-IaC.name
  virtual_network_name = azurerm_virtual_network.vnet-lz-hub.name
  address_prefixes     = [local.subnet1_cidr]
}

resource "azurerm_subnet" "bastion-subnet" {
  name                 = "AzureBastionSubnet"
  resource_group_name  = azurerm_resource_group.Secure-Landing-Zone-IaC.name
  virtual_network_name = azurerm_virtual_network.vnet-lz-hub.name
  address_prefixes     = [local.bastion_subnet_cidr]
  #checkov:skip=CKV2_AZURE_31
}

resource "azurerm_network_security_group" "nsg-hub" {
  name                = "nsg-hub"
  location            = azurerm_resource_group.Secure-Landing-Zone-IaC.location
  resource_group_name = azurerm_resource_group.Secure-Landing-Zone-IaC.name
  tags                = local.tags
}

resource "azurerm_subnet_network_security_group_association" "subnet1-nsg-association" {
  subnet_id                 = azurerm_subnet.subnet1.id
  network_security_group_id = azurerm_network_security_group.nsg-hub.id
}

resource "azurerm_private_dns_zone_virtual_network_link" "private-zone-link-vnet-hub" {
  name                 = "private-zone-link-vnet-hub"
  private_dns_zone_id  = azurerm_private_dns_zone.private-zone.id
  virtual_network_id   = azurerm_virtual_network.vnet-lz-hub.id
  registration_enabled = false

  tags = local.tags
}

