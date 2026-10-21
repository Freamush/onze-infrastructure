variable "HUB-IP-CIDR" {
  description = "The IP address to be used for the resource."
  type        = string
  default     = "192.168.0.0/16"
}

variable "username" {
  description = "The name of the VM user"
  type        = string
}

variable "username2" {
  description = "The name of the VM user"
  type        = string
}

variable "public_key" {
  description = "Public Key for VM user"
  type        = string
  default     = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC1/hOe8sQYN+bNtI2Aei/nI19xL3BgDgA9Jw/9WwsXSTLvgQWVlgaZIgEREFieCo6Wjb0z8TvS0D9iNeJt2TobOdPUl0e/GUykNIlTIzwjLSq7QKZBMxBJgghh0f3RdNUGHkkXGpxjJB/ewat7ud/PBWWSkhq9emx3OEGy0Ny18SXxknNDDokKPR4lWiOmBrCpGfrSWFXlmSEJKLVK1Dtrj2kCqyXsMCbaCgZFvm5JXUAnX+oA1vjBRbzrX5eiZibogGYVidkFprOjQJRx84GWQvOjUvEAuh3iZOmnNMFiineJS7WoiUZnpY+wz4sgR3cRFlHHD1YAgYt0hnDvPSDaYfIRYBxmV9mKmYXXAyLuCyJoZESU8G4rMlFLayuiF2v9A2lq7LO9vzikpFGUKlQz9ZlU9xruMe/fZ/ZdDgrK6m2o1YixjWMDj5d72zT/cH94u/3sOrC4xf3BetjiEnUh5EEKmsxf/Y+35NZp3JXcGgcdAUECzwyVgyMOwP/eEHtbzICxfoJRlP/GkxI5hd26OTBFb9dzq8kwaGRA6pdw3Ejk9B6jKRC+2259TWcRDZ4Dsy/fkoCeqiXGd0T9fbvFoESqZMSnpiRrRqjAlAlt2dGEgLAQKIZBzHwSxvWqOIt20ktaEJXQjEJFEk+nl02FyDMics34U7BqljQkL1oXGw=="
}

variable "SPOKE1-IP-CIDR" {
  description = "The IP address to be used for the resource."
  type        = string
  default     = "10.0.0.0/16"
}

variable "SPOKE2-IP-CIDR" {
  description = "The IP address to be used for the resource."
  type        = string
  default     = "172.16.0.0/16"
}

variable "SPOKE3-IP-CIDR" {
  type    = string
  default = "10.1.0.0/16"
}

variable "SPOKE4-IP-CIDR" {
  type    = string
  default = "172.17.0.0/16"
}

variable "SPOKE5-IP-CIDR" {
  type    = string
  default = "172.18.0.0/16"
}

variable "VM2-PRIVATE-IP" {
  description = "The private IP address to be used for the VM."
  type        = string
  default     = "10.1.1.5"
}

variable "VM-PRIVATE-IP" {
  description = "The private IP address to be used for the VM."
  type        = string
  default     = "10.0.1.5"
}

variable "FW-IP-CIDR" {
  description = "The private IP address to be used for the Firewall."
  type        = string
  default     = "192.168.2.0/26"
}

locals {
  subnet1_cidr        = cidrsubnet(var.HUB-IP-CIDR, 8, 1)
  subnet2_cidr        = cidrsubnet(var.SPOKE1-IP-CIDR, 8, 1)
  subnet3_cidr        = cidrsubnet(var.SPOKE2-IP-CIDR, 8, 1)
  subnet4_cird        = cidrsubnet(var.SPOKE3-IP-CIDR, 8, 1)
  subnet5_cird        = cidrsubnet(var.SPOKE4-IP-CIDR, 8, 1)
  subnet6_cird        = cidrsubnet(var.SPOKE5-IP-CIDR, 8, 1)
  bastion_subnet_cidr = cidrsubnet(var.HUB-IP-CIDR, 10, 0)
}


locals {
  tags = {
    project     = "landing-zone"
    env         = "dev"
    owner       = "fream"
  }
}

variable "ALERT_EMAIL" {
  description = "action group email"
  type        = string
  sensitive   = true
}

variable "ALERT_EMAIL2" {
  description = "action group email"
  type        = string
  sensitive   = true
}