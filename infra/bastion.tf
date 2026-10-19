resource "azurerm_bastion_host" "bastion_host" {
  name                = "bastion_host"
  location            = azurerm_resource_group.Secure-Landing-Zone-IaC.location
  resource_group_name = azurerm_resource_group.Secure-Landing-Zone-IaC.name
  sku                 = "Standard"

  tunneling_enabled = true

  ip_configuration {
    name                 = "bastion_ip_config"
    subnet_id            = azurerm_subnet.bastion-subnet.id
    public_ip_address_id = azurerm_public_ip.bastion-public-ip.id
  }
  tags = local.tags
}

resource "azurerm_public_ip" "bastion-public-ip" {
  name                = "bastion-public-ip"
  location            = azurerm_resource_group.Secure-Landing-Zone-IaC.location
  resource_group_name = azurerm_resource_group.Secure-Landing-Zone-IaC.name
  allocation_method   = "Static"
  sku                 = "Standard"

  tags = local.tags
}