data "azurerm_resource_group" "SLZ-ArcMachines" {
  name = "SLZ-ArcMachines"
}

data "azurerm_arc_machine" "arc_dc_entra" {
  name                = "DC-ENTRA"
  resource_group_name = data.azurerm_resource_group.SLZ-ArcMachines.name
}

data "azurerm_arc_machine" "ubuntu_devstation" {
  name                = "logcollector"
  resource_group_name = data.azurerm_resource_group.SLZ-ArcMachines.name
}

data "azurerm_arc_machine" "win-pc01" {
  name                = "PC01"
  resource_group_name = data.azurerm_resource_group.SLZ-ArcMachines.name
}

data "azurerm_arc_machine" "win-pc02" {
  name                = "PC02"
  resource_group_name = data.azurerm_resource_group.SLZ-ArcMachines.name
}

data "azurerm_arc_machine" "DC" {
  name                = "DC"
  resource_group_name = data.azurerm_resource_group.SLZ-ArcMachines.name
}


resource "azurerm_arc_machine_extension" "arc_ama_ubuntu" {
  name           = "AzureMonitorLinuxAgent"
  arc_machine_id = data.azurerm_arc_machine.ubuntu_devstation.id
  location       = data.azurerm_resource_group.SLZ-ArcMachines.location
  publisher      = "Microsoft.Azure.Monitor"
  type           = "AzureMonitorLinuxAgent"

  tags = local.tags
}

resource "azurerm_arc_machine_extension" "arc_ama_dc" {
  name           = "AzureMonitorWindowsAgent"
  arc_machine_id = data.azurerm_arc_machine.DC.id
  location       = data.azurerm_resource_group.SLZ-ArcMachines.location
  publisher      = "Microsoft.Azure.Monitor"
  type           = "AzureMonitorWindowsAgent"

  tags = local.tags
}

resource "azurerm_arc_machine_extension" "arc_ama_pc01" {
  name           = "AzureMonitorWindowsAgent"
  arc_machine_id = data.azurerm_arc_machine.win-pc01.id
  location       = data.azurerm_resource_group.SLZ-ArcMachines.location
  publisher      = "Microsoft.Azure.Monitor"
  type           = "AzureMonitorWindowsAgent"

  tags = local.tags
}

resource "azurerm_arc_machine_extension" "arc_ama_pc02" {
  name           = "AzureMonitorWindowsAgent"
  arc_machine_id = data.azurerm_arc_machine.win-pc02.id
  location       = data.azurerm_resource_group.SLZ-ArcMachines.location
  publisher      = "Microsoft.Azure.Monitor"
  type           = "AzureMonitorWindowsAgent"

  tags = local.tags
}

resource "azurerm_arc_machine_extension" "arc_ama_entra" {
  name           = "AzureMonitorWindowsAgent"
  arc_machine_id = data.azurerm_arc_machine.arc_dc_entra.id
  location       = data.azurerm_arc_machine.arc_dc_entra.location
  publisher      = "Microsoft.Azure.Monitor"
  type           = "AzureMonitorWindowsAgent"

  tags = local.tags
}


