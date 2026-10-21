resource "azurerm_container_registry" "acr" {
  name                = "acr_slz_onze"
  resource_group_name = azurerm_resource_group.Secure-Landing-Zone-Apps.name
  location            = azurerm_resource_group.Secure-Landing-Zone-Apps.location
  sku                 = "Basic"
  admin_enabled       = false
  tags                = local.tags
}

resource "azurerm_container_app_environment" "cae-lz-onze" {
  name                               = "cae_lz_onze"
  resource_group_name                = azurerm_resource_group.Secure-Landing-Zone-Apps.name
  location                           = azurerm_resource_group.Secure-Landing-Zone-Apps.location
  logs_destination                   = "log-analytics"
  log_analytics_workspace_id         = azurerm_log_analytics_workspace.log_space.id
  internal_load_balancer_enabled     = true
  infrastructure_resource_group_name = "Secure-Landing-Zone-Apps-Infra"
  infrastructure_subnet_id           = module.spoke5.subnet.id

  workload_profile {
    name                  = "Consumption"
    workload_profile_type = "Consumption"
  }

  tags = local.tags
}
