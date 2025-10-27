// Package azure provides centralized Azure OpenAI configuration, validation, and secret management
// following the DRY principle and Eos patterns (ASSESS → INTERVENE → EVALUATE)
package azure

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/environment"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/secrets"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	consulapi "github.com/hashicorp/consul/api"
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
// If secretManager is nil, it will initialize one automatically via environment discovery
func NewConfigManager(rc *eos_io.RuntimeContext, secretManager *secrets.SecretManager, serviceName string) *ConfigManager {
	return &ConfigManager{
		rc:            rc,
		secretManager: secretManager, // May be nil - will initialize on demand
		config: &OpenAIConfig{
			ServiceName: serviceName,
			APIVersion:  "2024-02-15-preview", // Default API version
		},
	}
}

// discoverEnvironment discovers the current Eos environment configuration
func (cm *ConfigManager) discoverEnvironment(ctx context.Context) (*environment.EnvironmentConfig, error) {
	logger := otelzap.Ctx(ctx)
	logger.Debug("Discovering Eos environment")

	envConfig, err := environment.DiscoverEnvironment(cm.rc)
	if err != nil {
		return nil, fmt.Errorf("failed to discover environment: %w", err)
	}

	return envConfig, nil
}

// ensureEnvironment ensures the environment is set in config
func (cm *ConfigManager) ensureEnvironment(ctx context.Context) error {
	if cm.config.Environment != "" {
		return nil // Already set
	}

	logger := otelzap.Ctx(ctx)
	logger.Debug("Environment not set, discovering")

	envConfig, err := cm.discoverEnvironment(ctx)
	if err != nil {
		return err
	}

	cm.config.Environment = envConfig.Environment
	logger.Debug("Environment discovered", zap.String("environment", cm.config.Environment))
	return nil
}

// ensureSecretManager initializes secret manager on demand if not provided
func (cm *ConfigManager) ensureSecretManager(ctx context.Context) error {
	if cm.secretManager != nil {
		return nil // Already initialized
	}

	logger := otelzap.Ctx(ctx)
	logger.Debug("Secret manager not provided, initializing via environment discovery")

	// Discover environment
	envConfig, err := cm.discoverEnvironment(ctx)
	if err != nil {
		return fmt.Errorf("failed to discover environment: %w", err)
	}

	// Set environment in config if not set
	if cm.config.Environment == "" {
		cm.config.Environment = envConfig.Environment
	}

	// Initialize secret manager
	secretManager, err := secrets.NewSecretManager(cm.rc, envConfig)
	if err != nil {
		return fmt.Errorf("failed to initialize secret manager: %w", err)
	}

	cm.secretManager = secretManager
	logger.Debug("Secret manager initialized successfully", zap.String("backend", "vault"))
	return nil
}

// getConsulClient creates a Consul client for KV storage
func (cm *ConfigManager) getConsulClient() (*consulapi.Client, error) {
	// Use default Consul configuration (localhost:8500)
	config := consulapi.DefaultConfig()

	client, err := consulapi.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create Consul client: %w", err)
	}

	return client, nil
}

// Configure interactively configures Azure OpenAI with smart auto-detection
// ASSESS → INFORM → CONSENT → INTERVENE → EVALUATE pattern
func (cm *ConfigManager) Configure(ctx context.Context, existingConfig *OpenAIConfig) (*OpenAIConfig, error) {
	logger := otelzap.Ctx(ctx)

	// ASSESS: Initialize secret manager if needed
	if err := cm.ensureSecretManager(ctx); err != nil {
		logger.Warn("Failed to initialize secret manager, will prompt for API key", zap.Error(err))
	}

	// ASSESS: Discover environment if not set
	if cm.config.Environment == "" {
		if err := cm.ensureEnvironment(ctx); err != nil {
			logger.Warn("Failed to discover environment, using 'production'", zap.Error(err))
			cm.config.Environment = "production"
		}
	}

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

	// PERSIST: Store non-secret configuration in Consul KV
	if err := cm.storeConfigInConsul(ctx); err != nil {
		logger.Warn("Failed to store configuration in Consul KV", zap.Error(err))
		// Don't fail - Consul might not be available yet
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

// storeConfigInConsul stores non-secret configuration in Consul KV
func (cm *ConfigManager) storeConfigInConsul(ctx context.Context) error {
	logger := otelzap.Ctx(ctx)

	// Check if Consul is available
	consulClient, err := cm.getConsulClient()
	if err != nil {
		logger.Debug("Consul not available, skipping KV storage", zap.Error(err))
		return nil // Graceful degradation
	}

	logger.Info("Storing Azure OpenAI configuration in Consul KV")

	// Use the standalone function from consul.go
	if err := StoreConfigInConsul(ctx, consulClient, cm.config); err != nil {
		return fmt.Errorf("failed to store config in Consul: %w", err)
	}

	logger.Info("✓ Azure OpenAI configuration stored in Consul KV successfully")
	return nil
}

// storeAPIKeyInVault stores the API key in Vault
func (cm *ConfigManager) storeAPIKeyInVault() error {
	logger := otelzap.Ctx(cm.rc.Ctx)

	if cm.secretManager == nil {
		logger.Warn("Secret manager not initialized, skipping Vault storage")
		return nil
	}

	logger.Info("Storing Azure OpenAI API key in Vault",
		zap.String("service", cm.config.ServiceName),
		zap.String("environment", cm.config.Environment))

	// Use unified StoreSecret() method - handles path format automatically
	// This replaces the old pattern of manually constructing paths
	if err := cm.secretManager.StoreSecret(
		cm.rc.Ctx,
		cm.config.ServiceName,
		"azure_api_key",
		cm.config.APIKey,
		secrets.SecretTypeAPIKey,
	); err != nil {
		logger.Error("Failed to store API key in Vault", zap.Error(err))
		return fmt.Errorf("failed to store API key in Vault: %w", err)
	}

	logger.Info("✓ Azure OpenAI API key stored in Vault successfully")
	return nil
}

// retrieveAPIKeyFromVault retrieves the API key from Vault
// If Vault fails, creates a fallback .env file with proper permissions (0640)
func (cm *ConfigManager) retrieveAPIKeyFromVault() (string, error) {
	logger := otelzap.Ctx(cm.rc.Ctx)

	if cm.secretManager == nil {
		return "", fmt.Errorf("secret manager not initialized")
	}

	logger.Debug("Retrieving Azure OpenAI API key from Vault",
		zap.String("service", cm.config.ServiceName),
		zap.String("environment", cm.config.Environment))

	// Use unified GetSecret() method - handles path format automatically
	// This replaces the old pattern of manually constructing paths
	apiKey, err := cm.secretManager.GetSecret(cm.rc.Ctx, cm.config.ServiceName, "azure_api_key")
	if err != nil {
		logger.Warn("Failed to retrieve API key from Vault, will create fallback .env file",
			zap.Error(err))
		return cm.createFallbackEnvFile()
	}

	logger.Debug("✓ Retrieved API key from Vault successfully")
	return apiKey, nil
}

// createFallbackEnvFile creates a fallback .env file when Vault is unavailable
// This ensures the command still works even if Vault is down
func (cm *ConfigManager) createFallbackEnvFile() (string, error) {
	logger := otelzap.Ctx(cm.rc.Ctx)

	// Determine fallback directory based on service
	fallbackDir := fmt.Sprintf("/opt/%s", cm.config.ServiceName)

	logger.Warn("Creating fallback .env file due to Vault unavailability",
		zap.String("directory", fallbackDir),
		zap.String("service", cm.config.ServiceName))

	// This allows the command to continue working even if Vault is down
	envContent := fmt.Sprintf(`# Azure OpenAI Configuration (Fallback)
# Generated by Eos due to Vault unavailability
# WARNING: This file contains sensitive credentials - secure appropriately
# Recommended: Fix Vault and delete this file

AZURE_OPENAI_ENDPOINT=%s
AZURE_OPENAI_API_VERSION=%s
AZURE_OPENAI_CHAT_DEPLOYMENT=%s
AZURE_OPENAI_EMBEDDINGS_DEPLOYMENT=%s
# TODO: Add your API key here manually
AZURE_OPENAI_API_KEY=

# Instructions:
# 1. Add your Azure OpenAI API key to the AZURE_OPENAI_API_KEY variable above
# 2. This file has 0640 permissions (owner read/write, group read, others none)
# 3. When Vault is fixed, re-run the configuration command to migrate to Vault
`,
		cm.config.Endpoint,
		cm.config.APIVersion,
		cm.config.ChatDeployment,
		cm.config.EmbeddingsDeployment,
	)

	// Create .env file with secure permissions (0640)
	envFilePath := fallbackDir + "/.env.azure_openai"
	if err := os.WriteFile(envFilePath, []byte(envContent), 0640); err != nil {
		return "", fmt.Errorf("failed to create fallback .env file: %w", err)
	}

	logger.Warn("Fallback .env file created - please add API key manually",
		zap.String("path", envFilePath),
		zap.String("permissions", "0640"))

	logger.Info("terminal prompt: Vault is unavailable - fallback .env file created")
	logger.Info("terminal prompt: Please edit the file and add your API key manually:")
	logger.Info("terminal prompt:   " + envFilePath)

	// Return empty string to indicate manual intervention needed
	// The calling code will handle the empty API key appropriately
	return "", fmt.Errorf("Vault unavailable - fallback .env file created at %s (requires manual API key)", envFilePath)
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
