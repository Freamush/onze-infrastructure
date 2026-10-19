variable "name" { type = string }

variable "rg_name" { type = string }
variable "location" { type = string }


variable "log_space_id" { type = string }
variable "log_space_name" { type = string }

variable "target_machine_id" { type = string }

variable "tags" {
  type    = map(string)
  default = {}
}