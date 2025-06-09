// pkg/llm/variables.tf

variable "prefix" {
  description = "A name prefix for all resources (e.g. project or team name)"
  type        = string
}

variable "environment" {
  description = "Deployment environment (e.g. dev, staging, prod)"
  type        = string

}

variable "location" {
  description = "Azure region to deploy into"
  type        = string
}

variable "resource_group_name" {
  description = "Base name for the Resource Group"
  type        = string
}

variable "openai_account_name" {
  description = "Name for the Azure Cognitive/OpenAI account"
  type        = string
}

variable "deployment_name" {
  description = "Name of the OpenAI deployment (model)"
  type        = string
}