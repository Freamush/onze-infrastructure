resource "azurerm_monitor_data_collection_rule" "azmon-dcr-linux" {
  name                = "dcr-${var.name}"
  location            = var.location
  resource_group_name = var.rg_name
  kind                = "Linux"

  destinations {
    log_analytics {
      workspace_resource_id = var.log_space_id
      name                  = var.log_space_name
    }
  }

  data_flow {
    streams      = ["Microsoft-Syslog"]
    destinations = [var.log_space_name]
  }

  data_sources {
    syslog {
      name           = "syslogDataSource"
      streams        = ["Microsoft-Syslog"]
      facility_names = ["auth", "authpriv", "cron", "daemon", "kern", "syslog", "user"]
      log_levels     = ["Warning", "Error", "Critical", "Alert", "Emergency"]
    }
  }
  tags = var.tags
}

resource "azurerm_monitor_data_collection_rule_association" "dcra-linux" {
  name                    = "${var.name}-association"
  target_resource_id      = var.target_machine_id
  data_collection_rule_id = azurerm_monitor_data_collection_rule.azmon-dcr-linux.id

}