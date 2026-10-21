resource "azurerm_resource_group" "Secure-Landing-Zone-IaC" {
  name     = "Secure-Landing-Zone-IaC"
  location = "Sweden Central"
  tags     = local.tags
}
resource "azurerm_resource_group" "Secure-Landing-Zone-Monitor" {
  name     = "Secure-Landing-Zone-Monitor"
  location = "Sweden Central"
  tags     = local.tags
}
resource "azurerm_resource_group" "Secure-Landing-Zone-Backup" {
  name     = "Secure-Landing-Zone-Backup"
  location = azurerm_resource_group.Secure-Landing-Zone-IaC.location
  tags     = local.tags
}

resource "azurerm_resource_group" "Secure-Landing-Zone-Apps" {
  name     = "Secure-Landing-Zone-Apps"
  location = azurerm_resource_group.Secure-Landing-Zone-IaC.location
  tags     = local.tags
}



module "spoke1" {
  source              = "./modules/spoke"
  name                = "vnet-lz-spoke1"
  rg_name             = azurerm_resource_group.Secure-Landing-Zone-IaC.name
  location            = azurerm_resource_group.Secure-Landing-Zone-IaC.location
  hub_id              = azurerm_virtual_network.vnet-lz-hub.id
  hub_name            = azurerm_virtual_network.vnet-lz-hub.name
  vnet_cidr           = var.SPOKE1-IP-CIDR
  subnet_cidr         = local.subnet2_cidr
  firewall_private_ip = azurerm_firewall.az-firewall.ip_configuration[0].private_ip_address
  tags                = local.tags
  private_zone_ids = {
    blob   = azurerm_private_dns_zone.private-zone.id
    backup = azurerm_private_dns_zone.backups-zone.id
  }
  depends_on = [azurerm_virtual_network.vnet-lz-hub]
}

module "spoke2" {
  source                  = "./modules/spoke"
  name                    = "vnet-lz-spoke2"
  rg_name                 = azurerm_resource_group.Secure-Landing-Zone-IaC.name
  location                = azurerm_resource_group.Secure-Landing-Zone-IaC.location
  hub_id                  = azurerm_virtual_network.vnet-lz-hub.id
  hub_name                = azurerm_virtual_network.vnet-lz-hub.name
  vnet_cidr               = var.SPOKE2-IP-CIDR
  subnet_cidr             = local.subnet3_cidr
  firewall_private_ip     = azurerm_firewall.az-firewall.ip_configuration[0].private_ip_address
  tags                    = local.tags
  private_endpoint_policy = "Enabled"
  route_prefix            = var.SPOKE1-IP-CIDR
  private_zone_ids = {
    blob = azurerm_private_dns_zone.private-zone.id
  }
  depends_on = [azurerm_virtual_network.vnet-lz-hub]
}


module "spoke3" {
  source              = "./modules/spoke"
  name                = "vnet-lz-spoke3"
  rg_name             = azurerm_resource_group.Secure-Landing-Zone-IaC.name
  location            = azurerm_resource_group.Secure-Landing-Zone-IaC.location
  hub_id              = azurerm_virtual_network.vnet-lz-hub.id
  hub_name            = azurerm_virtual_network.vnet-lz-hub.name
  vnet_cidr           = var.SPOKE3-IP-CIDR
  subnet_cidr         = local.subnet4_cird
  firewall_private_ip = azurerm_firewall.az-firewall.ip_configuration[0].private_ip_address
  tags                = local.tags
  route_prefix        = "0.0.0.0/0"
  private_zone_ids = {
    blob   = azurerm_private_dns_zone.private-zone.id
    backup = azurerm_private_dns_zone.backups-zone.id
  }
  depends_on = [azurerm_virtual_network.vnet-lz-hub]
}

module "spoke4" {
  source                  = "./modules/spoke"
  name                    = "vnet-lz-spoke4"
  rg_name                 = azurerm_resource_group.Secure-Landing-Zone-IaC.name
  location                = azurerm_resource_group.Secure-Landing-Zone-IaC.location
  hub_id                  = azurerm_virtual_network.vnet-lz-hub.id
  hub_name                = azurerm_virtual_network.vnet-lz-hub.name
  vnet_cidr               = var.SPOKE4-IP-CIDR
  subnet_cidr             = local.subnet5_cird
  firewall_private_ip     = azurerm_firewall.az-firewall.ip_configuration[0].private_ip_address
  tags                    = local.tags
  route_prefix            = "0.0.0.0/0"
  private_endpoint_policy = "Enabled"
  private_zone_ids = {
    blob   = azurerm_private_dns_zone.private-zone.id
    backup = azurerm_private_dns_zone.backups-zone.id
  }
  depends_on = [azurerm_virtual_network.vnet-lz-hub]
}

module "spoke5" {
  source                  = "./modules/spoke"
  name                    = "vnet-lz-spoke5"
  rg_name                 = azurerm_resource_group.Secure-Landing-Zone-IaC.name
  location                = azurerm_resource_group.Secure-Landing-Zone-IaC.location
  hub_id                  = azurerm_virtual_network.vnet-lz-hub.id
  hub_name                = azurerm_virtual_network.vnet-lz-hub.name
  vnet_cidr               = var.SPOKE5-IP-CIDR
  subnet_cidr             = local.subnet6_cird
  firewall_private_ip     = azurerm_firewall.az-firewall.ip_configuration[0].private_ip_address
  tags                    = local.tags
  route_prefix            = "0.0.0.0/0"
  private_endpoint_policy = "Enabled"
  private_zone_ids = {
    blob   = azurerm_private_dns_zone.private-zone.id
    backup = azurerm_private_dns_zone.backups-zone.id
  }
  delegation = {
    name    = "Microsoft.App/environments"
    actions = ["Microsoft.Network/virtualNetworks/subnets/join/action"]
  }
  depends_on = [azurerm_virtual_network.vnet-lz-hub]
}

resource "azurerm_private_dns_zone" "private-zone" {
  name                = "privatelink.blob.core.windows.net"
  resource_group_name = azurerm_resource_group.Secure-Landing-Zone-IaC.name

  tags = local.tags
}

resource "azurerm_private_dns_zone" "backups-zone" {
  name                = "privatelink.sdc.backup.windowsazure.com"
  resource_group_name = azurerm_resource_group.Secure-Landing-Zone-IaC.name

  tags = local.tags
}
