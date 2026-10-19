resource "azurerm_storage_account" "slzstorageiac" {
  account_kind        = "StorageV2"
  name                = "slzstorageiac"
  resource_group_name = azurerm_resource_group.Secure-Landing-Zone-IaC.name

  location                 = azurerm_resource_group.Secure-Landing-Zone-IaC.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  #checkov:skip=CKV_AZURE_206
  #checkov:skip=CKV_AZURE_33
  #checkov:skip=CKV2_AZURE_1 CMK would require Key Vault
  min_tls_version                 = "TLS1_2"
  allow_nested_items_to_be_public = false
  local_user_enabled              = false
  public_network_access_enabled   = false
  shared_access_key_enabled       = false
  tags                            = local.tags

  blob_properties {
    delete_retention_policy {
      days = 7
    }
    container_delete_retention_policy {
      days = 7
    }
  }

}

resource "azurerm_storage_container" "slzstorageiac-container" {
  name                  = "slzstorageiac-container"
  storage_account_id    = azurerm_storage_account.slzstorageiac.id
  container_access_type = "private"

  #checkov:skip=CKV2_AZURE_21 todo
}

resource "azurerm_private_endpoint" "pe-spoke2" {
  name                = "pe-spoke2"
  location            = azurerm_resource_group.Secure-Landing-Zone-IaC.location
  resource_group_name = azurerm_resource_group.Secure-Landing-Zone-IaC.name
  subnet_id           = module.spoke2.subnet.id


  private_service_connection {
    name                           = "pe-spoke2-connection"
    private_connection_resource_id = azurerm_storage_account.slzstorageiac.id
    is_manual_connection           = false
    subresource_names              = ["blob"]
  }

  private_dns_zone_group {
    name                 = "pe-spoke2-dns-zone-group"
    private_dns_zone_ids = [azurerm_private_dns_zone.private-zone.id]
  }
  tags = local.tags
}