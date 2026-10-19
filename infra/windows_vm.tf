resource "azurerm_network_interface" "nic-spoke3" {
  name                = "nic-spoke3"
  location            = azurerm_resource_group.Secure-Landing-Zone-IaC.location
  resource_group_name = azurerm_resource_group.Secure-Landing-Zone-IaC.name

  ip_configuration {
    name                          = "internal"
    subnet_id                     = module.spoke3.subnet.id
    private_ip_address_allocation = "Static"
    private_ip_address            = var.VM2-PRIVATE-IP
  }

  tags = local.tags
}

resource "azurerm_virtual_machine_extension" "aad_login" {
  name                       = "AADLoginForWindows"
  virtual_machine_id         = azurerm_windows_virtual_machine.vm_spoke3.id
  publisher                  = "Microsoft.Azure.ActiveDirectory"
  type                       = "AADLoginForWindows"
  type_handler_version       = "2.0"
  auto_upgrade_minor_version = true

  tags = local.tags
}

resource "azurerm_virtual_machine_extension" "ama" {
  name                       = "AzureMonitorWindowsAgent"
  virtual_machine_id         = azurerm_windows_virtual_machine.vm_spoke3.id
  publisher                  = "Microsoft.Azure.Monitor"
  type                       = "AzureMonitorWindowsAgent"
  type_handler_version       = "1.10"
  auto_upgrade_minor_version = true

  tags = local.tags
}

resource "azurerm_windows_virtual_machine" "vm_spoke3" {
  name                = "win-workstation"
  resource_group_name = azurerm_resource_group.Secure-Landing-Zone-IaC.name
  location            = azurerm_resource_group.Secure-Landing-Zone-IaC.location
  size                = "Standard_B2ts_v2"

  admin_username = "azureadmin"
  admin_password = data.azurerm_key_vault_secret.vm_pass.value

  identity {
    type = "SystemAssigned"
  }

  network_interface_ids = [azurerm_network_interface.nic-spoke3.id]

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  source_image_reference {
    publisher = "MicrosoftWindowsServer"
    offer     = "WindowsServer"
    sku       = "2022-datacenter-azure-edition"
    version   = "latest"
  }

  tags = local.tags
}

