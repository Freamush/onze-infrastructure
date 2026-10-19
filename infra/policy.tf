resource "azurerm_policy_definition" "no_untagged_resources" {
  name         = "no-untagged-resources"
  policy_type  = "Custom"
  mode         = "Indexed"
  display_name = "Deny untagged resources"
  description  = "This policy denies the creation of resources that do not have the required tags."

  policy_rule = jsonencode({
    if = {
      anyOf = [
        { field = "tags['env']", exists = false },
        { field = "tags['project']", exists = false },
        { field = "tags['owner']", exists = false },
      ]
    }
    then = { effect = "deny" }
  })
}

resource "azurerm_resource_group_policy_assignment" "require_tag" {
  name                 = "require-environment-tag"
  resource_group_id    = azurerm_resource_group.Secure-Landing-Zone-IaC.id
  policy_definition_id = azurerm_policy_definition.no_untagged_resources.id

}

resource "azurerm_policy_definition" "no_public_ip" {
  name         = "no-public-ip-on-nic"
  policy_type  = "Custom"
  mode         = "All"
  display_name = "Disallow Public IP on NIC"
  description  = "Denies network interfaces that have a public IP attached"

  policy_rule = jsonencode({
    if = {
      allOf = [
        { field = "type", equals = "Microsoft.Network/networkInterfaces" },
        { not = {
          field   = "Microsoft.Network/networkInterfaces/ipconfigurations[*].publicIpAddress.id"
          notLike = "*"
        } }
      ]
    }
    then = { effect = "deny" }
  })
}

resource "azurerm_resource_group_policy_assignment" "no_public_ip_assignment" {
  name                 = "no_public_ip_assignment"
  resource_group_id    = azurerm_resource_group.Secure-Landing-Zone-IaC.id
  policy_definition_id = azurerm_policy_definition.no_public_ip.id

}