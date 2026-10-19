data "azuread_group" "it_group" {
  display_name     = "GG-IT"
  security_enabled = true
}

resource "azurerm_role_assignment" "it_vm_login" {
  scope                = azurerm_virtual_machine.vm-spoke1.id
  role_definition_name = "Virtual Machine User Login"
  principal_id         = data.azuread_group.it_group.object_id
}

resource "azurerm_role_assignment" "it_vm2_login" {
  scope                = azurerm_windows_virtual_machine.vm_spoke3.id
  role_definition_name = "Virtual Machine User Login"
  principal_id         = data.azuread_group.it_group.object_id
}


data "azuread_group" "soc_group" {
  display_name     = "SOC-TEAM"
  security_enabled = true
}


resource "azurerm_role_assignment" "soc_sentinel_assignment" {
  scope                = azurerm_resource_group.Secure-Landing-Zone-Monitor.id
  role_definition_name = "Microsoft Sentinel Contributor"
  principal_id         = data.azuread_group.soc_group.object_id
}

resource "azurerm_role_assignment" "soc_reader_assignment" {
  scope                = azurerm_resource_group.Secure-Landing-Zone-Monitor.id
  role_definition_name = "Reader"
  principal_id         = data.azuread_group.soc_group.object_id
}