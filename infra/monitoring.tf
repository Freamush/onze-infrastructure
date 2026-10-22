resource "azurerm_log_analytics_workspace" "log_space" {
  name                = "azure-log-analytics"
  resource_group_name = azurerm_resource_group.Secure-Landing-Zone-Monitor.name
  location            = azurerm_resource_group.Secure-Landing-Zone-Monitor.location
  sku                 = "PerGB2018"
  retention_in_days   = 30
  daily_quota_gb      = 1
  tags                = local.tags

}


resource "azurerm_monitor_diagnostic_setting" "fw-diagnostics" {
  name                           = "firewall-diagnostics"
  target_resource_id             = azurerm_firewall.az-firewall.id
  log_analytics_workspace_id     = azurerm_log_analytics_workspace.log_space.id
  log_analytics_destination_type = "Dedicated"

  enabled_log {
    category = "AZFWNetworkRule"
  }

  enabled_log {
    category = "AZFWDnsQuery"
  }

  enabled_log {
    category = "AZFWThreatIntel"
  }

  enabled_log {
    category = "AZFWApplicationRule"
  }
}

resource "azurerm_monitor_diagnostic_setting" "storage-diagnostics" {
  name                       = "storage-diagnostics"
  target_resource_id         = "${azurerm_storage_account.slzstorageiac.id}/blobServices/default"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.log_space.id

  enabled_log {
    category = "StorageDelete"
  }
  enabled_log {
    category = "StorageRead"
  }
  enabled_log {
    category = "StorageWrite"
  }


}

resource "azurerm_monitor_action_group" "action_group" {
  name                = "action_group"
  resource_group_name = azurerm_resource_group.Secure-Landing-Zone-Monitor.name
  short_name          = "AG-1"
  email_receiver {
    name          = var.username
    email_address = var.ALERT_EMAIL
  }
  email_receiver {
    name          = var.username2
    email_address = var.ALERT_EMAIL2
  }
  tags = local.tags
}

resource "azurerm_monitor_scheduled_query_rules_alert_v2" "alert1" {
  name                              = "deny_alert"
  location                          = azurerm_resource_group.Secure-Landing-Zone-Monitor.location
  resource_group_name               = azurerm_resource_group.Secure-Landing-Zone-Monitor.name
  scopes                            = [azurerm_log_analytics_workspace.log_space.id]
  severity                          = 2
  evaluation_frequency              = "PT5M"
  window_duration                   = "PT10M"
  mute_actions_after_alert_duration = "PT10M"
  criteria {
    query                   = <<-QUERY
      AZFWApplicationRule
      | where Action == "Deny"
      | summarize DenyCount = count() by SourceIp
      | where DenyCount > 5
      QUERY
    time_aggregation_method = "Count"
    threshold               = 0
    operator                = "GreaterThan"
  }
  action {
    action_groups = [azurerm_monitor_action_group.action_group.id]
  }
  tags = local.tags
}


resource "azurerm_monitor_scheduled_query_rules_alert_v2" "alert2" {
  name                              = "DRIFT_DETECTED"
  location                          = azurerm_resource_group.Secure-Landing-Zone-Monitor.location
  resource_group_name               = azurerm_resource_group.Secure-Landing-Zone-Monitor.name
  scopes                            = [azurerm_log_analytics_workspace.log_space.id]
  severity                          = 2
  evaluation_frequency              = "PT15M"
  window_duration                   = "PT30M"
  mute_actions_after_alert_duration = "PT6H"
  display_name                      = "ONZE infrastructure drift detected"
  description                       = "Azure resources no longer match the Terraform code on main. Check the caj-onze-drift job logs."
  criteria {
    query                   = <<-QUERY
      ContainerAppConsoleLogs_CL
      | where ContainerJobName_s == "caj-onze-drift"
      | where Log_s has "DRIFT_DETECTED"
      QUERY
    time_aggregation_method = "Count"
    threshold               = 0
    operator                = "GreaterThan"
  }
  action {
    action_groups = [azurerm_monitor_action_group.action_group.id]
  }
  tags = local.tags
}


locals {
  windows_machines = {
    "vm-spoke3" = azurerm_windows_virtual_machine.vm_spoke3.id
    "dc-entra"  = data.azurerm_arc_machine.arc_dc_entra.id
    "pc01"      = data.azurerm_arc_machine.win-pc01.id
    "pc02"      = data.azurerm_arc_machine.win-pc02.id
    "DC"        = data.azurerm_arc_machine.DC.id
  }
}

module "windows_dcr" {
  for_each          = local.windows_machines
  source            = "./modules/win_dcr"
  name              = each.key
  rg_name           = azurerm_resource_group.Secure-Landing-Zone-IaC.name
  location          = azurerm_resource_group.Secure-Landing-Zone-IaC.location
  log_space_name    = azurerm_log_analytics_workspace.log_space.name
  log_space_id      = azurerm_log_analytics_workspace.log_space.id
  target_machine_id = each.value
  tags              = local.tags

  depends_on = [
    azurerm_virtual_machine_extension.ama,
    azurerm_arc_machine_extension.arc_ama_dc,
    azurerm_arc_machine_extension.arc_ama_pc01,
    azurerm_arc_machine_extension.arc_ama_pc02,
    azurerm_arc_machine_extension.arc_ama_entra,
  ]
}

locals {
  linux_machines = {
    "ubuntu_dev" = data.azurerm_arc_machine.ubuntu_devstation.id
    "vm-spoke1"  = azurerm_virtual_machine.vm-spoke1.id
  }
}

module "linux_dcr" {
  for_each          = local.linux_machines
  source            = "./modules/linux_dcr"
  name              = each.key
  rg_name           = azurerm_resource_group.Secure-Landing-Zone-IaC.name
  location          = azurerm_resource_group.Secure-Landing-Zone-IaC.location
  log_space_name    = azurerm_log_analytics_workspace.log_space.name
  log_space_id      = azurerm_log_analytics_workspace.log_space.id
  target_machine_id = each.value
  tags              = local.tags

  depends_on = [
    azurerm_arc_machine_extension.arc_ama_ubuntu,
    azurerm_virtual_machine_extension.linux_ama,
  ]
}

