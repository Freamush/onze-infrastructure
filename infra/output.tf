
output "Resource-Group-Output" {
  description = "The Azure Resource Group Name"
  value       = azurerm_resource_group.Secure-Landing-Zone-IaC.name
}

output "bastion_public_ip_address" {
  description = "The public IP address of the Azure Bastion host"
  value       = azurerm_public_ip.bastion-public-ip.ip_address
}

output "work_space_id" {
  description = "Workspace log analytics id"
  value       = azurerm_log_analytics_workspace.log_space.id
}
