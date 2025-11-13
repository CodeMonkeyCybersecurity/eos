// pkg/llm/main.tf

terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.70"
    }
    local = {
      source  = "hashicorp/local"
      version = "~> 2.1"
    }
  }
}

provider "azurerm" {
  features {}
}

# Optionally add a random suffix to avoid name collisions
resource "random_id" "suffix" {
  byte_length = 2
}

locals {
  rg_name       = "${var.resource_group_name}-${var.environment}-${random_id.suffix.hex}"
  account_name  = "${var.prefix}-${var.environment}-openai"
  deployment_id = "${var.deployment_name}-${var.environment}"
}

# 1. Resource Group
resource "azurerm_resource_group" "rg" {
  name     = local.rg_name
  location = var.location
}

# 2. Cognitive Services Account (OpenAI)
resource "azurerm_cognitive_account" "openai" {
  name                = local.account_name
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  kind                = "OpenAI"
  sku_name            = "S0"
}

# 3. Model Deployment
resource "azurerm_openai_deployment" "gpt4" {
  name                = local.deployment_id
  resource_group_name = azurerm_resource_group.rg.name
  account_name        = azurerm_cognitive_account.openai.name

  model {
    name = "gpt-4"
  }

  scale {
    scale_type = "Standard"
    capacity   = 1
  }
}

# 4. Emit a .env file for your Go app
resource "local_file" "env_file" {
  filename = "${path.module}/wazuh.env"
  content  = <<-EOF
    AZURE_API_KEY=${azurerm_cognitive_account.openai.primary_access_key}
    AZURE_ENDPOINT=${azurerm_cognitive_account.openai.endpoint}
    AZURE_DEPLOYMENT=${azurerm_openai_deployment.gpt4.name}
  EOF
}