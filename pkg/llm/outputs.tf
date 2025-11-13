// pkg/llm/outputs.tf

output "azure_api_key" {
  description = "Primary key for the OpenAI account"
  value       = azurerm_cognitive_account.openai.primary_access_key
  sensitive   = true
}

output "azure_endpoint" {
  description = "REST endpoint for the OpenAI account"
  value       = azurerm_cognitive_account.openai.endpoint
}

output "deployment_name" {
  description = "Name of the model deployment"
  value       = azurerm_openai_deployment.gpt4.name
}