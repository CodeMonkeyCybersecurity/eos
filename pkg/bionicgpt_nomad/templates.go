// pkg/bionicgpt_nomad/templates.go - Template management for Nomad job generation

package bionicgpt_nomad

import (
	"embed"
)

// Embed all Nomad job templates
//
//go:embed templates/*.tmpl
var templatesFS embed.FS

// buildTemplateData creates the data map for template rendering
func (ei *EnterpriseInstaller) buildTemplateData() map[string]interface{} {
	return map[string]interface{}{
		// Core deployment settings
		"Namespace":  ei.config.Namespace,
		"Datacenter": "dc1", // TODO: Make configurable if needed
		"Region":     "global",

		// Domain and authentication
		"Domain":  ei.config.Domain,
		"AuthURL": ei.config.AuthURL,

		// Authentik groups
		"SuperadminGroup": ei.config.SuperadminGroup,
		"DemoGroup":       ei.config.DemoGroup,
		"GroupPrefix":     ei.config.GroupPrefix,

		// Azure OpenAI configuration
		"AzureEndpoint":             ei.config.AzureEndpoint,
		"AzureChatDeployment":       ei.config.AzureChatDeployment,
		"AzureEmbeddingsDeployment": ei.config.AzureEmbeddingsDeployment,

		// Local embeddings
		"UseLocalEmbeddings":   ei.config.UseLocalEmbeddings,
		"LocalEmbeddingsModel": ei.config.LocalEmbeddingsModel,

		// Infrastructure addresses
		"NomadAddress":  ei.config.NomadAddress,
		"ConsulAddress": ei.config.ConsulAddress,

		// Vault secret paths (for documentation in templates)
		"VaultDBSecretPath":      "secret/data/bionicgpt/db",
		"VaultOAuthSecretPath":   "secret/data/bionicgpt/oauth",
		"VaultAzureSecretPath":   "secret/data/bionicgpt/azure",
		"VaultLiteLLMSecretPath": "secret/data/bionicgpt/litellm",
	}
}
