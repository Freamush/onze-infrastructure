resource "azurerm_container_registry" "acr" {
  name                = "acrslzonze"
  resource_group_name = azurerm_resource_group.Secure-Landing-Zone-Apps.name
  location            = azurerm_resource_group.Secure-Landing-Zone-Apps.location
  sku                 = "Basic"
  admin_enabled       = false
  tags                = local.tags
  #checkov:skip=CKV_AZURE_165 No need in geo replication policy for non-prod project
  #checkov:skip=CKV_AZURE_163:Images are scanned with Trivy in the build pipeline before push
  #checkov:skip=CKV_AZURE_164:Images are signed and verified with cosign in the build pipeline
  #checkov:skip=CKV_AZURE_139:Private access requires Premium SKU; 
  #checkov:skip=CKV_AZURE_166:Quarantine policy requires Premium SKU
  #checkov:skip=CKV_AZURE_167:Retention policy requires Premium SKU
  #checkov:skip=CKV_AZURE_233:Zone redundancy requires Premium SKU
  #checkov:skip=CKV_AZURE_237:Dedicated data endpoints require Premium SKU

}


resource "azurerm_container_app_environment" "cae-lz-onze" {
  name                               = "caeslzonze"
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
