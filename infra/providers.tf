terraform {
  required_version = ">=1.12.0"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 5.0"
    }
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 3.1.0"
    }
  }
  backend "azurerm" {
    resource_group_name  = "tf-remote-state-rg"
    storage_account_name = "remotestatestorageslz"
    container_name       = "tfstate"
    key                  = "slz-prod.tfstate"
    use_azuread_auth     = true
  }
}

provider "azuread" {}

provider "azurerm" {
  features {}
}

data "azurerm_client_config" "current" {}

data "azurerm_subscription" "current" {}
