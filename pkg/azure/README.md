# pkg/azure

*Last Updated: 2025-10-21*

Centralized Azure OpenAI configuration, validation, and secret management for Eos.

## Purpose

This package provides a **DRY (Don't Repeat Yourself)** approach to Azure OpenAI configuration across all Eos services (BionicGPT, OpenWebUI, Iris, etc.) with:

- **Smart URL parsing**: Auto-detects deployment names and API versions from full completion URLs
- **Comprehensive validation**: Validates endpoints, API keys, and deployment names
- **Vault integration**: Stores API keys securely in Vault (secrets)
- **Consul KV integration**: Stores non-secret configuration in Consul KV
- **Connection testing**: Tests Azure OpenAI connectivity before proceeding
- **Human-centric UX**: Clear prompts, helpful error messages, auto-detection

## Architecture

### Storage Strategy

Following Eos principles (see [CLAUDE.md#secret-and-configuration-management](../../CLAUDE.md#secret-and-configuration-management)):

**Secrets (Vault)**:
- `services/{environment}/{service}/azure_openai_api_key` - API key

**Configuration (Consul KV)**:
- `service/{service}/config/azure_openai/endpoint` - Base URL
- `service/{service}/config/azure_openai/api_version` - API version
- `service/{service}/config/azure_openai/chat_deployment` - Chat model deployment name
- `service/{service}/config/azure_openai/embeddings_deployment` - Embeddings model deployment name (optional)
- `service/{service}/config/azure_openai/environment` - Environment metadata

### Delivery

Use **Consul Template** (recommended) or **Vault Agent** to render configuration files for services.

## Usage

### Basic Configuration

```go
import (
    "github.com/CodeMonkeyCybersecurity/eos/pkg/azure"
    "github.com/CodeMonkeyCybersecurity/eos/pkg/secrets"
)

// Initialize secret manager
secretManager, err := secrets.NewSecretManager(rc, envConfig)
if err != nil {
    return err
}

// Create Azure OpenAI configuration manager
azureManager := azure.NewConfigManager(rc, secretManager, "bionicgpt")

// Configure interactively
config, err := azureManager.Configure(ctx, nil)
if err != nil {
    return err
}

// Config now contains:
// - config.Endpoint (https://resource.openai.azure.com)
// - config.ChatDeployment (gpt-4)
// - config.EmbeddingsDeployment (text-embedding-ada-002 or empty)
// - config.APIKey (validated)
// - config.APIVersion (2024-02-15-preview)
```

### With Existing Configuration (Flags)

```go
existingConfig := &azure.OpenAIConfig{
    Endpoint: flags.AzureEndpoint,
    ChatDeployment: flags.AzureChatDeployment,
    APIKey: flags.AzureAPIKey,
    ServiceName: "openwebui",
    Environment: "production",
}

azureManager := azure.NewConfigManager(rc, secretManager, "openwebui")
config, err := azureManager.Configure(ctx, existingConfig)
```

### Smart URL Parsing

The package automatically detects and parses full completion URLs:

**Input**:
```
https://myresource.openai.azure.com/openai/deployments/gpt-4/chat/completions?api-version=2024-02-15
```

**Auto-detected**:
- Endpoint: `https://myresource.openai.azure.com`
- Chat Deployment: `gpt-4`
- API Version: `2024-02-15`

### Consul KV Storage

```go
import "github.com/hashicorp/consul/api"

// Store configuration in Consul KV
consulClient, _ := api.NewClient(api.DefaultConfig())
err := azure.StoreConfigInConsul(ctx, consulClient, config)

// Load configuration from Consul KV
config, err := azure.LoadConfigFromConsul(ctx, consulClient, "bionicgpt")

// Delete configuration from Consul KV
err := azure.DeleteConfigFromConsul(ctx, consulClient, "bionicgpt")
```

### Validation

```go
// Validate endpoint
err := azure.ValidateEndpoint("https://myresource.openai.azure.com")

// Validate API key
err := azure.ValidateAPIKey("sk-...")

// Validate deployment name
err := azure.ValidateDeployment("gpt-4")

// Redact for logging
redacted := azure.RedactEndpoint("https://myresource.openai.azure.com")
// Returns: "myresource.openai.azure.com"

redactedKey := azure.RedactAPIKey("sk-1234567890abcdef1234567890abcdef")
// Returns: "sk-1...cdef"
```

## Supported URL Formats

### Standard Azure OpenAI
- `https://{resource}.openai.azure.com`
- Example: `https://mycompany.openai.azure.com`

### Azure AI Foundry (New)
- `https://{project}.services.ai.azure.com`
- Example: `https://my-ai-project.services.ai.azure.com`

### Full Completion URLs (Auto-parsed)
- `https://{resource}.openai.azure.com/openai/deployments/{deployment}/chat/completions?api-version={version}`
- `https://{project}.services.ai.azure.com/api/projects/{project}/...`

## API Key Formats

Supports all Azure OpenAI API key formats:
- **Legacy**: 32 hex characters
- **Standard**: 43-44 base64 characters
- **Azure AI Foundry**: 88+ base64 characters

## Error Handling

All errors use `eos_err.NewUserError()` with actionable remediation steps:

```
Azure OpenAI authentication failed (401 Unauthorized)
Your API key is invalid or expired
Fix: Go to Azure Portal → Your OpenAI Resource → Keys and Endpoint → Regenerate Key
```

## Migration from Existing Code

### Before (Scattered across services)
```go
// pkg/bionicgpt/install.go - duplicated validation
func (bgi *BionicGPTInstaller) promptForAzureConfig(ctx context.Context) error {
    // 80+ lines of prompting and validation
    endpoint, err := eos_io.PromptInput(...)
    bgi.config.AzureEndpoint = shared.SanitizeURL(endpoint)
    // More duplication...
}

// pkg/openwebui/install.go - duplicated validation
func (owi *OpenWebUIInstaller) promptForAzureConfig(ctx context.Context) error {
    // 100+ lines of prompting, URL parsing, validation
    // Same logic, slightly different implementation
}

// pkg/iris/config.go - duplicated validation
func PromptAzureConfig(...) error {
    // Another 60+ lines of similar logic
}
```

### After (Centralized, DRY)
```go
// All services
azureManager := azure.NewConfigManager(rc, secretManager, serviceName)
config, err := azureManager.Configure(ctx, existingConfig)
```

**Lines of code reduction**: ~240 lines → ~3 lines (80x reduction!)

## Testing

```bash
# Build package
go build ./pkg/azure/...

# Run tests (when implemented)
go test -v ./pkg/azure/...

# Verify formatting
gofmt -l pkg/azure/*.go

# Verify with vet
go vet ./pkg/azure/...
```

## Related Packages

- [pkg/secrets](../secrets/) - Secret management (Vault backend)
- [pkg/interaction](../interaction/) - User prompts and consent
- [pkg/eos_io](../eos_io/) - I/O utilities (PromptInput)
- [pkg/shared](../shared/) - URL sanitization (SanitizeURL)

## Future Enhancements

- [ ] Complete Vault backend integration in `pkg/secrets/manager.go`
- [ ] Add Azure OpenAI SDK integration for advanced operations
- [ ] Add model listing/verification
- [ ] Add quota checking
- [ ] Add deployment health checks
- [ ] Add unit tests
- [ ] Add integration tests with mock Vault/Consul

## References

- [Azure OpenAI Service Documentation](https://learn.microsoft.com/en-us/azure/ai-services/openai/)
- [Azure AI Foundry Documentation](https://learn.microsoft.com/en-us/azure/ai-studio/)
- [Eos Secret Management](../../CLAUDE.md#secret-and-configuration-management)

---

*"Cybersecurity. With humans."*
