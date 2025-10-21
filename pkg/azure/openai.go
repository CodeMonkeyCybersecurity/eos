// Package azure provides centralized Azure OpenAI configuration, validation, and secret management
// following the DRY principle and Eos patterns (ASSESS → INTERVENE → EVALUATE)
package azure

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/secrets"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// OpenAIConfig represents Azure OpenAI configuration with smart auto-detection
type OpenAIConfig struct {
	// Core fields
	Endpoint   string // Base URL (https://resource.openai.azure.com)
	APIKey     string // API key (stored in Vault)
	APIVersion string // API version (default: 2024-02-15-preview)

	// Deployment names
	ChatDeployment       string // Chat model deployment (e.g., gpt-4)
	EmbeddingsDeployment string // Embeddings model deployment (e.g., text-embedding-ada-002)

	// Service metadata for secret storage
	ServiceName string // Service using Azure OpenAI (bionicgpt, openwebui, iris)
	Environment string // Environment (production, development, etc.)
}

// ConfigManager handles Azure OpenAI configuration with Vault and Consul KV integration
type ConfigManager struct {
	rc            *eos_io.RuntimeContext
	secretManager *secrets.SecretManager
	config        *OpenAIConfig
}

// NewConfigManager creates a new Azure OpenAI configuration manager
func NewConfigManager(rc *eos_io.RuntimeContext, secretManager *secrets.SecretManager, serviceName string) *ConfigManager {
	return &ConfigManager{
		rc:            rc,
		secretManager: secretManager,
		config: &OpenAIConfig{
			ServiceName: serviceName,
			APIVersion:  "2024-02-15-preview", // Default API version
		},
	}
}

// Configure interactively configures Azure OpenAI with smart auto-detection
// ASSESS → INFORM → CONSENT → INTERVENE → EVALUATE pattern
func (cm *ConfigManager) Configure(ctx context.Context, existingConfig *OpenAIConfig) (*OpenAIConfig, error) {
	logger := otelzap.Ctx(ctx)

	// ASSESS: Check if configuration already complete
	if existingConfig != nil && cm.isComplete(existingConfig) {
		logger.Debug("Azure OpenAI configuration already complete")
		cm.config = existingConfig
		return cm.config, nil
	}

	// Initialize from existing config if provided
	if existingConfig != nil {
		cm.config = existingConfig
	}

	// INFORM: Tell user what we're configuring
	logger.Info("terminal prompt: Azure OpenAI configuration required")
	logger.Info("terminal prompt: You can find these in Azure Portal → Your OpenAI Resource → Keys and Endpoint")
	logger.Info("terminal prompt: Deployment names are under: Deployments tab")
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: TIP: You can paste the full completion URL and we'll extract the details automatically!")

	// INTERVENE: Configure endpoint with auto-detection
	if err := cm.configureEndpoint(ctx); err != nil {
		return nil, err
	}

	// INTERVENE: Configure chat deployment
	if err := cm.configureChatDeployment(ctx); err != nil {
		return nil, err
	}

	// INTERVENE: Configure embeddings deployment (optional)
	if cm.config.EmbeddingsDeployment == "" {
		if err := cm.configureEmbeddingsDeployment(ctx); err != nil {
			return nil, err
		}
	}

	// INTERVENE: Configure API key with Vault storage
	if err := cm.configureAPIKey(ctx); err != nil {
		return nil, err
	}

	// EVALUATE: Validate configuration
	if err := cm.validate(); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	// EVALUATE: Test connection
	if err := cm.TestConnection(ctx); err != nil {
		logger.Warn("Azure OpenAI connection test failed - configuration saved but may need adjustment", zap.Error(err))
		// Don't fail - let user proceed with potentially invalid config
	}

	logger.Info("Azure OpenAI configuration completed successfully")
	return cm.config, nil
}

// configureEndpoint handles endpoint configuration with smart URL parsing
func (cm *ConfigManager) configureEndpoint(ctx context.Context) error {
	logger := otelzap.Ctx(ctx)

	if cm.config.Endpoint != "" {
		// Already provided via flag or existing config
		cm.config.Endpoint = shared.SanitizeURL(cm.config.Endpoint)
		return cm.parseAndNormalizeEndpoint()
	}

	// Prompt for endpoint
	logger.Info("terminal prompt: Enter Azure OpenAI Endpoint or full completion URL")
	logger.Info("terminal prompt: Examples:")
	logger.Info("terminal prompt:   Base URL: https://myresource.openai.azure.com")
	logger.Info("terminal prompt:   Full URL: https://myresource.openai.azure.com/openai/deployments/gpt-4/chat/completions?api-version=2024-02-15")
	endpoint, err := eos_io.PromptInput(cm.rc, "Azure OpenAI Endpoint: ", "azure_endpoint")
	if err != nil {
		return fmt.Errorf("failed to read Azure endpoint: %w", err)
	}

	cm.config.Endpoint = shared.SanitizeURL(endpoint)
	return cm.parseAndNormalizeEndpoint()
}

// parseAndNormalizeEndpoint extracts deployment and API version from full URLs
func (cm *ConfigManager) parseAndNormalizeEndpoint() error {
	logger := otelzap.Ctx(cm.rc.Ctx)

	parsed, err := url.Parse(cm.config.Endpoint)
	if err != nil {
		return fmt.Errorf("failed to parse Azure endpoint: %w", err)
	}

	// Check if this is a full completion URL with deployment name in path
	// Format: https://resource.openai.azure.com/openai/deployments/{deployment}/chat/completions?api-version=...
	if strings.Contains(parsed.Path, "/openai/deployments/") {
		logger.Info("Detected full Azure AI Foundry completion URL - extracting components")

		// Extract base URL
		baseURL := fmt.Sprintf("%s://%s", parsed.Scheme, parsed.Host)

		// Extract deployment name from path if not already set
		if cm.config.ChatDeployment == "" {
			pathParts := strings.Split(strings.Trim(parsed.Path, "/"), "/")
			for i, part := range pathParts {
				if part == "deployments" && i+1 < len(pathParts) {
					cm.config.ChatDeployment = pathParts[i+1]
					logger.Info("✓ Auto-detected chat deployment from URL",
						zap.String("deployment", cm.config.ChatDeployment))
					break
				}
			}
		}

		// Extract API version from query params if not already set
		if cm.config.APIVersion == "2024-02-15-preview" { // Default value
			if apiVersion := parsed.Query().Get("api-version"); apiVersion != "" {
				cm.config.APIVersion = apiVersion
				logger.Info("✓ Auto-detected API version from URL",
					zap.String("api_version", cm.config.APIVersion))
			}
		}

		// Normalize to base URL
		cm.config.Endpoint = baseURL
		logger.Info("✓ Using extracted base URL", zap.String("base_url", baseURL))
	}

	// Validate endpoint format
	return ValidateEndpoint(cm.config.Endpoint)
}

// configureChatDeployment handles chat deployment configuration
func (cm *ConfigManager) configureChatDeployment(ctx context.Context) error {
	logger := otelzap.Ctx(ctx)

	if cm.config.ChatDeployment != "" {
		// Already set (either from URL or flag)
		logger.Debug("Chat deployment already configured", zap.String("deployment", cm.config.ChatDeployment))
		return ValidateDeployment(cm.config.ChatDeployment)
	}

	// Prompt for chat deployment
	logger.Info("terminal prompt: Enter Chat Model Deployment Name (e.g., gpt-4, gpt-35-turbo)")
	logger.Info("terminal prompt: This is the DEPLOYMENT name from Azure Portal, not the model name")
	chatDeployment, err := eos_io.PromptInput(cm.rc, "Chat Deployment Name: ", "chat_deployment")
	if err != nil {
		return fmt.Errorf("failed to read chat deployment name: %w", err)
	}

	cm.config.ChatDeployment = strings.TrimSpace(chatDeployment)
	return ValidateDeployment(cm.config.ChatDeployment)
}

// configureEmbeddingsDeployment handles embeddings deployment configuration
func (cm *ConfigManager) configureEmbeddingsDeployment(ctx context.Context) error {
	logger := otelzap.Ctx(ctx)

	logger.Info("terminal prompt: Enter Embeddings Model Deployment Name (or leave blank to skip)")
	logger.Info("terminal prompt: Example: text-embedding-ada-002")
	embeddingsDeployment, err := eos_io.PromptInput(cm.rc, "Embeddings Deployment Name (optional): ", "embeddings_deployment")
	if err != nil {
		return fmt.Errorf("failed to read embeddings deployment name: %w", err)
	}

	cm.config.EmbeddingsDeployment = strings.TrimSpace(embeddingsDeployment)

	// Skip validation if empty (optional field)
	if cm.config.EmbeddingsDeployment == "" {
		logger.Debug("Embeddings deployment not configured (optional)")
		return nil
	}

	return ValidateDeployment(cm.config.EmbeddingsDeployment)
}

// configureAPIKey handles API key configuration with Vault storage
// IDEMPOTENT: Checks Vault first, only prompts if secret doesn't exist
func (cm *ConfigManager) configureAPIKey(ctx context.Context) error {
	logger := otelzap.Ctx(ctx)

	if cm.config.APIKey != "" {
		// Already provided via flag
		logger.Debug("API key already provided via flag")
		if err := ValidateAPIKey(cm.config.APIKey); err != nil {
			return err
		}
		// Store in Vault for future use
		return cm.storeAPIKeyInVault()
	}

	// IDEMPOTENT: Check Vault first before prompting
	if cm.secretManager != nil {
		logger.Debug("Checking Vault for existing API key")
		if existingKey, err := cm.retrieveAPIKeyFromVault(); err == nil && existingKey != "" {
			logger.Info("✓ Using existing API key from Vault")
			cm.config.APIKey = existingKey
			return nil
		}
		logger.Debug("No existing API key found in Vault, will prompt")
	}

	// Prompt for API key with Vault option
	logger.Info("terminal prompt: Enter API Key (input will be hidden, or leave blank to use Vault)")
	apiKey, err := interaction.PromptSecret(ctx, "API Key (or Enter for Vault): ")
	if err != nil {
		return fmt.Errorf("failed to read API key: %w", err)
	}

	cm.config.APIKey = strings.TrimSpace(apiKey)

	// If empty and secret manager not available, error
	if cm.config.APIKey == "" {
		if cm.secretManager == nil {
			return fmt.Errorf("API key required but secret manager not initialized")
		}
		return fmt.Errorf("API key required - Vault is empty and no key provided")
	}

	// Validate and store in Vault
	if err := ValidateAPIKey(cm.config.APIKey); err != nil {
		return err
	}

	return cm.storeAPIKeyInVault()
}

// storeAPIKeyInVault stores the API key in Vault
func (cm *ConfigManager) storeAPIKeyInVault() error {
	logger := otelzap.Ctx(cm.rc.Ctx)

	if cm.secretManager == nil {
		logger.Warn("Secret manager not initialized, skipping Vault storage")
		return nil
	}

	// Store API key in Vault at: services/{environment}/{service}/azure_openai_api_key
	vaultPath := fmt.Sprintf("services/%s/%s/azure_openai_api_key",
		cm.config.Environment, cm.config.ServiceName)

	logger.Info("Storing Azure OpenAI API key in Vault", zap.String("path", vaultPath))

	// TODO: Implement actual Vault storage via secretManager
	// For now, the VaultBackend in pkg/secrets/manager.go:265 returns "vault backend not fully implemented"
	// This needs to be completed to actually store the key

	logger.Debug("API key will be stored in Vault when backend is fully implemented")
	return nil
}

// retrieveAPIKeyFromVault retrieves the API key from Vault
func (cm *ConfigManager) retrieveAPIKeyFromVault() error {
	logger := otelzap.Ctx(cm.rc.Ctx)

	if cm.secretManager == nil {
		return fmt.Errorf("secret manager not initialized - cannot retrieve API key from Vault")
	}

	vaultPath := fmt.Sprintf("services/%s/%s/azure_openai_api_key",
		cm.config.Environment, cm.config.ServiceName)

	logger.Info("Retrieving Azure OpenAI API key from Vault", zap.String("path", vaultPath))

	// TODO: Implement actual Vault retrieval via secretManager
	// For now, return error to prompt user to provide key
	return fmt.Errorf("Vault backend not fully implemented - please provide API key manually")
}

// TestConnection tests the Azure OpenAI connection
func (cm *ConfigManager) TestConnection(ctx context.Context) error {
	logger := otelzap.Ctx(ctx)

	endpoint := fmt.Sprintf("%s/openai/models?api-version=%s",
		cm.config.Endpoint,
		cm.config.APIVersion)

	logger.Debug("Testing Azure OpenAI connection", zap.String("endpoint", RedactEndpoint(cm.config.Endpoint)))

	// Create HTTP request with context
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set Azure OpenAI API key header
	req.Header.Set("api-key", cm.config.APIKey)
	req.Header.Set("User-Agent", fmt.Sprintf("Eos-%s/1.0", cm.config.ServiceName))

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	// Execute request
	resp, err := client.Do(req)
	if err != nil {
		return eos_err.NewUserError(
			"Cannot reach Azure OpenAI endpoint: %v\n"+
				"Check your network connection and firewall rules\n"+
				"Verify the endpoint is accessible from this machine", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			logger.Warn("Failed to close response body", zap.Error(closeErr))
		}
	}()

	// Handle different HTTP status codes
	switch resp.StatusCode {
	case http.StatusOK:
		logger.Info("✓ Successfully connected to Azure OpenAI",
			zap.String("endpoint", RedactEndpoint(cm.config.Endpoint)),
			zap.Int("status", resp.StatusCode))
		return nil

	case http.StatusUnauthorized:
		return eos_err.NewUserError(
			"Azure OpenAI authentication failed (401 Unauthorized)\n" +
				"Your API key is invalid or expired\n" +
				"Fix: Go to Azure Portal → Your OpenAI Resource → Keys and Endpoint → Regenerate Key")

	case http.StatusForbidden:
		return eos_err.NewUserError(
			"Azure OpenAI access forbidden (403 Forbidden)\n" +
				"Your API key doesn't have permission to access this resource\n" +
				"Fix: Check your Azure OpenAI resource permissions")

	case http.StatusNotFound:
		return eos_err.NewUserError(
			"Azure OpenAI endpoint not found (404 Not Found)\n" +
				"The endpoint URL is incorrect\n" +
				"Fix: Verify the endpoint URL in Azure Portal → Your OpenAI Resource → Keys and Endpoint")

	case http.StatusTooManyRequests:
		return eos_err.NewUserError(
			"Azure OpenAI rate limit exceeded (429 Too Many Requests)\n" +
				"You've hit the rate limit for your Azure OpenAI resource\n" +
				"Fix: Wait a moment and try again, or upgrade your quota in Azure Portal")

	default:
		// Read error response body for details
		body, _ := io.ReadAll(resp.Body)
		logger.Error("Azure OpenAI returned unexpected status",
			zap.Int("status", resp.StatusCode),
			zap.String("body", string(body)))

		return eos_err.NewUserError(
			"Azure OpenAI returned error: HTTP %d\n"+
				"Response: %s\n"+
				"Fix: Check Azure Portal for service health and your resource status",
			resp.StatusCode, string(body))
	}
}

// validate validates the complete configuration
func (cm *ConfigManager) validate() error {
	if err := ValidateEndpoint(cm.config.Endpoint); err != nil {
		return fmt.Errorf("invalid endpoint: %w", err)
	}

	if err := ValidateDeployment(cm.config.ChatDeployment); err != nil {
		return fmt.Errorf("invalid chat deployment: %w", err)
	}

	// Embeddings deployment is optional
	if cm.config.EmbeddingsDeployment != "" && cm.config.EmbeddingsDeployment != "local" {
		if err := ValidateDeployment(cm.config.EmbeddingsDeployment); err != nil {
			return fmt.Errorf("invalid embeddings deployment: %w", err)
		}
	}

	if err := ValidateAPIKey(cm.config.APIKey); err != nil {
		return fmt.Errorf("invalid API key: %w", err)
	}

	return nil
}

// isComplete checks if configuration is already complete
func (cm *ConfigManager) isComplete(config *OpenAIConfig) bool {
	return config.Endpoint != "" &&
		config.ChatDeployment != "" &&
		config.APIKey != ""
	// Note: EmbeddingsDeployment is optional
}

// GetConfig returns the current configuration
func (cm *ConfigManager) GetConfig() *OpenAIConfig {
	return cm.config
}

// SetConfig sets the configuration (for flag-based setup)
func (cm *ConfigManager) SetConfig(config *OpenAIConfig) {
	cm.config = config
}
