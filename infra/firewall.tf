resource "azurerm_firewall" "az-firewall" {
  name                = "slz-firewall"
  location            = azurerm_resource_group.Secure-Landing-Zone-IaC.location
  resource_group_name = azurerm_resource_group.Secure-Landing-Zone-IaC.name
  sku_name            = "AZFW_VNet"
  sku_tier            = "Standard"
  firewall_policy_id  = azurerm_firewall_policy.fw-policy.id
  threat_intel_mode   = "Deny"
  #checkov:skip=CKV_AZURE_220:Premium-only 
  #checkov:skip=CKV_AZURE_220:IDPS Premium-only

  ip_configuration {
    name                 = "ipconfig"
    subnet_id            = azurerm_subnet.fw-subnet.id
    public_ip_address_id = azurerm_public_ip.fw-public-ip.id
  }
  tags = local.tags
}

resource "azurerm_subnet" "fw-subnet" {
  name                 = "AzureFirewallSubnet"
  resource_group_name  = azurerm_resource_group.Secure-Landing-Zone-IaC.name
  virtual_network_name = azurerm_virtual_network.vnet-lz-hub.name
  address_prefixes     = [var.FW-IP-CIDR]
}

resource "azurerm_public_ip" "fw-public-ip" {
  name                = "fw-public-ip"
  location            = azurerm_resource_group.Secure-Landing-Zone-IaC.location
  resource_group_name = azurerm_resource_group.Secure-Landing-Zone-IaC.name
  allocation_method   = "Static"
  sku                 = "Standard"

  tags = local.tags
}

resource "azurerm_firewall_policy" "fw-policy" {
  name                     = "fw-policy"
  resource_group_name      = azurerm_resource_group.Secure-Landing-Zone-IaC.name
  location                 = azurerm_resource_group.Secure-Landing-Zone-IaC.location
  sku                      = "Standard"
  threat_intelligence_mode = "Deny"
  tags                     = local.tags
  #checkov:skip=CKV_AZURE_220:IDPS Premium-only
}

resource "azurerm_firewall_policy_rule_collection_group" "fw-rcg" {
  name               = "rcg-lz"
  firewall_policy_id = azurerm_firewall_policy.fw-policy.id
  priority           = 100

  network_rule_collection {
    name     = "allow-app-to-data"
    priority = 100
    action   = "Allow"

    rule {
      name                  = "allow-spoke1-to-spoke2-443"
      protocols             = ["TCP"]
      source_addresses      = [var.SPOKE1-IP-CIDR]
      destination_addresses = [var.SPOKE2-IP-CIDR]
      destination_ports     = ["443"]
    }
  }
  application_rule_collection {
    name     = "allow-app-egress"
    priority = 200
    action   = "Allow"

    rule {
      name             = "allow-web-egress"
      source_addresses = [var.SPOKE1-IP-CIDR]
      destination_fqdns = [
        "azure.archive.ubuntu.com",
        "archive.ubuntu.com",
        "security.ubuntu.com",
        "aka.ms",
        "packages.microsoft.com",
        "azurecliprod.blob.core.windows.net",
        "management.azure.com",
        "motd.ubuntu.com",
        "changelogs.ubuntu.com",
        "esm.ubuntu.com",
        "swedencentral.handler.control.monitor.azure.com",
        "global.handler.control.monitor.azure.com",
        "${azurerm_log_analytics_workspace.log_space.workspace_id}.ods.opinsights.azure.com",
        "login.microsoftonline.com",
        "dc.services.visualstudio.com"
      ]
      protocols {
        type = "Http"
        port = 80
      }
      protocols {
        type = "Https"
        port = 443
      }
    }

    rule {
      name             = "allow-entra-vm-login-spoke3"
      source_addresses = [var.SPOKE3-IP-CIDR]
      destination_fqdns = [
        "login.microsoftonline.com",
        "enterpriseregistration.windows.net",
        "device.login.microsoftonline.com",
        "pas.windows.net",
        "swedencentral.handler.control.monitor.azure.com",
        "global.handler.control.monitor.azure.com",
        "${azurerm_log_analytics_workspace.log_space.workspace_id}.ods.opinsights.azure.com",
        "dc.services.visualstudio.com",
        "*.microsoft.com",
        "*.digicert.com",
        "*.windowsupdate.com",
      ]
      protocols {
        type = "Https"
        port = 443
      }
      protocols {
        type = "Http"
        port = 80
      }
    }

    rule {
      name             = "allow-entra-vm-login-spoke5"
      source_addresses = [var.SPOKE5-IP-CIDR]
      destination_fqdns = [
        "mcr.microsoft.com",
        "*.data.mcr.microsoft.com",
        "*.login.microsoft.com",
        "*.identity.azure.net",
        "management.azure.com",
        "acrslzonze.azurecr.io",
        "*.blob.core.windows.net",
        "${azurerm_log_analytics_workspace.log_space.workspace_id}.ods.opinsights.azure.com",
        "swedencentral-shared.prod.warm.ingest.monitor.core.windows.net",
        "dc.services.visualstudio.com",
        "*.monitoring.core.windows.net",
        "github.com",
        "login.microsoftonline.com",
        "graph.microsoft.com",
        "registry.terraform.io",
        "releases.hashicorp.com",
      ]
      protocols {
        type = "Https"
        port = 443
      }
      protocols {
        type = "Http"
        port = 80
      }
    }

  }

}