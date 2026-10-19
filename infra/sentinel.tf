module "sentinel" {
  source  = "terraform-az-modules/sentinel/azurerm"
  version = "3.0.1"

  name                       = "sentinel"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.log_space.id
  location                   = azurerm_resource_group.Secure-Landing-Zone-Monitor.location
  tenant_id                  = data.azurerm_client_config.current.tenant_id
  subscription_id            = data.azurerm_client_config.current.subscription_id
  enable_mti_connector       = false
}