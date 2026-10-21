resource "azurerm_container_registry" "acr" {
  name                = "acrslzonze"
  resource_group_name = azurerm_resource_group.Secure-Landing-Zone-Apps.name
  location            = azurerm_resource_group.Secure-Landing-Zone-Apps.location
  sku                 = "Basic"
  admin_enabled       = false
  tags                = local.tags
  #checkov:skip=CKV_AZURE_165: No need in geo replication policy for non-prod project
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

data "azurerm_user_assigned_identity" "onze-plan-identity" {
  name                = "id-onze-plan"
  resource_group_name = data.azurerm_resource_group.SLZ-DeploymentRG.name
}

data "azurerm_resource_group" "SLZ-DeploymentRG" {
  name = "SLZ-DeploymentRG"
}

resource "azurerm_container_app_job" "caj-slz-onze" {
  name                         = "caj-onze-drift"
  resource_group_name          = azurerm_resource_group.Secure-Landing-Zone-Apps.name
  location                     = azurerm_resource_group.Secure-Landing-Zone-Apps.location
  container_app_environment_id = azurerm_container_app_environment.cae-lz-onze.id
  replica_timeout_in_seconds   = 900
  replica_retry_limit          = 0
  schedule_trigger_config {
    cron_expression          = "*/30 * * * *"
    parallelism              = 1
    replica_completion_count = 1
  }
  workload_profile_name = "Consumption"

  identity {
    type         = "UserAssigned"
    identity_ids = [data.azurerm_user_assigned_identity.onze-plan-identity.id]
  }

  registry {
    server   = azurerm_container_registry.acr.login_server
    identity = data.azurerm_user_assigned_identity.onze-plan-identity.id
  }

  lifecycle {
    ignore_changes = [template[0].container[0].image]
  }

  template {
    container {
      name   = "drift-checker"
      image  = "mcr.microsoft.com/k8se/quickstart-jobs:latest"
      cpu    = 1
      memory = "2Gi"
      env {
        name  = "ARM_CLIENT_ID"
        value = data.azurerm_user_assigned_identity.onze-plan-identity.client_id
      }

      env {
        name  = "ARM_TENANT_ID"
        value = data.azurerm_client_config.current.tenant_id
      }

      env {
        name  = "ARM_SUBSCRIPTION_ID"
        value = data.azurerm_client_config.current.subscription_id
      }

      env {
        name  = "ARM_USE_MSI"
        value = "true"
      }
      env {
        name  = "TF_VAR_ALERT_EMAIL"
        value = var.ALERT_EMAIL
      }
      env {
        name  = "TF_VAR_ALERT_EMAIL2"
        value = var.ALERT_EMAIL2
      }
      env {
        name  = "TF_VAR_username"
        value = var.username
      }
      env {
        name  = "TF_VAR_username2"
        value = var.username2
      }
    }
  }

  tags = local.tags
}
