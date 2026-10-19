resource "azurerm_monitor_data_collection_rule" "data_collection_rule" {
  name                = "dcr-${var.name}"
  location            = var.location
  resource_group_name = var.rg_name


  destinations {
    log_analytics {
      workspace_resource_id = var.log_space_id
      name                  = var.log_space_name
    }
  }

  data_flow {
    streams      = ["Microsoft-Event"]
    destinations = [var.log_space_name]
  }

  data_sources {
    windows_event_log {
      streams = ["Microsoft-Event"]
      x_path_queries = ["Application!*[System[(Level=1 or Level=2 or Level=3 or Level=4 or Level=0 or Level=5)]]",
        "Security!*[System[(band(Keywords,13510798882111488))]]",
      "System!*[System[(Level=1 or Level=2 or Level=3 or Level=4 or Level=0 or Level=5)]]"]
      name = "eventLogsDataSource"
    }
  }
  tags = var.tags
}

resource "azurerm_monitor_data_collection_rule_association" "dcra" {
  name                    = "${var.name}-association"
  target_resource_id      = var.target_machine_id
  data_collection_rule_id = azurerm_monitor_data_collection_rule.data_collection_rule.id

}