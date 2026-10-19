variable "name" { type = string }
variable "vnet_cidr" { type = string }
variable "subnet_cidr" { type = string }
variable "rg_name" { type = string }
variable "location" { type = string }
variable "tags" { type = map(string) }
variable "hub_id" { type = string }
variable "hub_name" { type = string }
variable "firewall_private_ip" { type = string }
variable "private_endpoint_policy" {
  type    = string
  default = null
}
variable "route_prefix" {
  type    = string
  default = "0.0.0.0/0"
}
variable "private_zone_ids" {
  type    = map(string)
  default = {}
}

