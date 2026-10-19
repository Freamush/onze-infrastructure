resource "azurerm_recovery_services_vault" "recovery_vault" {
  name                          = "recovery-vault"
  resource_group_name           = azurerm_resource_group.Secure-Landing-Zone-Backup.name
  location                      = azurerm_resource_group.Secure-Landing-Zone-Backup.location
  sku                           = "Standard"
  public_network_access_enabled = false

  storage_mode_type = "LocallyRedundant"
  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_backup_policy_vm" "backup_policy" {
  name                = "backup-policy"
  recovery_vault_name = azurerm_recovery_services_vault.recovery_vault.name
  resource_group_name = azurerm_resource_group.Secure-Landing-Zone-Backup.name

  backup {
    frequency = "Daily"
    time      = "23:00"
  }

  retention_daily {
    count = 10
  }
  retention_weekly {
    count    = 4
    weekdays = ["Sunday"]
  }
  retention_monthly {
    count    = 3
    weekdays = ["Sunday"]
    weeks    = ["Last"]
  }

  retention_yearly {
    count    = 1
    weekdays = ["Sunday"]
    weeks    = ["Last"]
    months   = ["January"]
  }
}

resource "azurerm_backup_protected_vm" "spoke1vm-protected" {
  recovery_vault_name = azurerm_recovery_services_vault.recovery_vault.name
  resource_group_name = azurerm_resource_group.Secure-Landing-Zone-Backup.name
  source_vm_id        = azurerm_virtual_machine.vm-spoke1.id
  backup_policy_id    = azurerm_backup_policy_vm.backup_policy.id

  depends_on = [azurerm_private_endpoint.pe-spoke4]
}

resource "azurerm_backup_protected_vm" "spoke3vm-protected" {
  recovery_vault_name = azurerm_recovery_services_vault.recovery_vault.name
  resource_group_name = azurerm_resource_group.Secure-Landing-Zone-Backup.name
  source_vm_id        = azurerm_windows_virtual_machine.vm_spoke3.id
  backup_policy_id    = azurerm_backup_policy_vm.backup_policy.id

  depends_on = [azurerm_private_endpoint.pe-spoke4]
}

resource "azurerm_private_endpoint" "pe-spoke4" {
  name                = "pe-spoke4"
  location            = azurerm_resource_group.Secure-Landing-Zone-IaC.location
  resource_group_name = azurerm_resource_group.Secure-Landing-Zone-IaC.name
  subnet_id           = module.spoke4.subnet.id


  private_service_connection {
    name                           = "pe-spoke4-connection"
    private_connection_resource_id = azurerm_recovery_services_vault.recovery_vault.id
    is_manual_connection           = false
    subresource_names              = ["AzureBackup"]
  }

  private_dns_zone_group {
    name                 = "pe-spoke4-dns-zone-group"
    private_dns_zone_ids = [azurerm_private_dns_zone.backups-zone.id]
  }
  tags = local.tags
}