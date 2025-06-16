// pkg/ai/config.go

package ai

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

// AIConfig represents the AI assistant configuration
type AIConfig struct {
	// Provider selection
	Provider string `yaml:"provider,omitempty"` // "anthropic" or "azure-openai"
	
	// Common configuration
	APIKey      string `yaml:"api_key,omitempty"`
	APIKeyVault string `yaml:"api_key_vault,omitempty"` // Vault path for API key
	BaseURL     string `yaml:"base_url,omitempty"`
	Model       string `yaml:"model,omitempty"`
	MaxTokens   int    `yaml:"max_tokens,omitempty"`
	Timeout     int    `yaml:"timeout,omitempty"`
	
	// Azure OpenAI specific configuration
	AzureEndpoint    string `yaml:"azure_endpoint,omitempty"`
	AzureAPIVersion  string `yaml:"azure_api_version,omitempty"`
	AzureDeployment  string `yaml:"azure_deployment,omitempty"`
}

// ConfigManager manages AI configuration
type ConfigManager struct {
	configPath string
	config     *AIConfig
}

// NewConfigManager creates a new configuration manager
func NewConfigManager() *ConfigManager {
	// Default config path in user's config directory
	configDir, err := os.UserConfigDir()
	if err != nil {
		configDir = os.Getenv("HOME")
	}
	
	configPath := filepath.Join(configDir, "eos", "ai-config.yaml")
	
	return &ConfigManager{
		configPath: configPath,
		config:     &AIConfig{},
	}
}

// LoadConfig loads the AI configuration from file
func (cm *ConfigManager) LoadConfig() error {
	// Ensure config directory exists
	configDir := filepath.Dir(cm.configPath)
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Check if config file exists
	if _, err := os.Stat(cm.configPath); os.IsNotExist(err) {
		// Create default config (Anthropic Claude)
		cm.config = &AIConfig{
			Provider:  "anthropic",
			BaseURL:   "https://api.anthropic.com/v1",
			Model:     "claude-3-sonnet-20240229",
			MaxTokens: 4096,
			Timeout:   60,
		}
		return nil
	}

	// Read config file
	data, err := os.ReadFile(cm.configPath)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	// Parse YAML
	if err := yaml.Unmarshal(data, cm.config); err != nil {
		return fmt.Errorf("failed to parse config file: %w", err)
	}

	return nil
}

// SaveConfig saves the AI configuration to file
func (cm *ConfigManager) SaveConfig() error {
	// Ensure config directory exists
	configDir := filepath.Dir(cm.configPath)
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Marshal to YAML
	data, err := yaml.Marshal(cm.config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	// Write to file with restricted permissions
	if err := os.WriteFile(cm.configPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// GetAPIKey retrieves the API key from config or environment
func (cm *ConfigManager) GetAPIKey(rc *eos_io.RuntimeContext) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Priority order:
	// 1. Environment variable (takes precedence)
	// 2. Vault (if configured)
	// 3. Config file
	
	// Check provider-specific environment variables first
	provider := cm.config.Provider
	if provider == "" {
		provider = "anthropic" // Default to Anthropic
	}
	
	// Provider-specific environment variables
	if provider == "azure-openai" {
		if apiKey := os.Getenv("AZURE_OPENAI_API_KEY"); apiKey != "" {
			logger.Debug("Using API key from AZURE_OPENAI_API_KEY environment variable")
			return apiKey, nil
		}
		if apiKey := os.Getenv("OPENAI_API_KEY"); apiKey != "" {
			logger.Debug("Using API key from OPENAI_API_KEY environment variable")
			return apiKey, nil
		}
	} else {
		// Anthropic/Claude environment variables
		if apiKey := os.Getenv("ANTHROPIC_API_KEY"); apiKey != "" {
			logger.Debug("Using API key from ANTHROPIC_API_KEY environment variable")
			return apiKey, nil
		}
		if apiKey := os.Getenv("CLAUDE_API_KEY"); apiKey != "" {
			logger.Debug("Using API key from CLAUDE_API_KEY environment variable")
			return apiKey, nil
		}
	}
	
	// Generic AI API key (works for both)
	if apiKey := os.Getenv("AI_API_KEY"); apiKey != "" {
		logger.Debug("Using API key from AI_API_KEY environment variable")
		return apiKey, nil
	}

	// Check Vault if configured
	if cm.config.APIKeyVault != "" {
		logger.Debug("Attempting to retrieve API key from Vault", zap.String("path", cm.config.APIKeyVault))
		// TODO: Implement Vault retrieval
		// apiKey, err := vault.GetSecret(rc, cm.config.APIKeyVault)
		// if err == nil && apiKey != "" {
		//     return apiKey, nil
		// }
	}

	// Check config file
	if cm.config.APIKey != "" {
		logger.Debug("Using API key from config file")
		return cm.config.APIKey, nil
	}

	return "", fmt.Errorf("AI API key not configured. Run 'eos ai configure' to set it up")
}

// SetAPIKey sets the API key in the configuration
func (cm *ConfigManager) SetAPIKey(apiKey string) error {
	cm.config.APIKey = apiKey
	return cm.SaveConfig()
}

// SetAPIKeyVault sets the Vault path for the API key
func (cm *ConfigManager) SetAPIKeyVault(vaultPath string) error {
	cm.config.APIKeyVault = vaultPath
	cm.config.APIKey = "" // Clear plaintext key when using Vault
	return cm.SaveConfig()
}

// GetConfig returns the current configuration
func (cm *ConfigManager) GetConfig() *AIConfig {
	return cm.config
}

// UpdateConfig updates configuration fields
func (cm *ConfigManager) UpdateConfig(updates map[string]any) error {
	for key, value := range updates {
		switch strings.ToLower(key) {
		case "provider":
			if v, ok := value.(string); ok {
				cm.config.Provider = v
			}
		case "api_key", "apikey":
			if v, ok := value.(string); ok {
				cm.config.APIKey = v
			}
		case "api_key_vault", "apikeyvault":
			if v, ok := value.(string); ok {
				cm.config.APIKeyVault = v
			}
		case "base_url", "baseurl":
			if v, ok := value.(string); ok {
				cm.config.BaseURL = v
			}
		case "model":
			if v, ok := value.(string); ok {
				cm.config.Model = v
			}
		case "max_tokens", "maxtokens":
			if v, ok := value.(int); ok {
				cm.config.MaxTokens = v
			}
		case "timeout":
			if v, ok := value.(int); ok {
				cm.config.Timeout = v
			}
		case "azure_endpoint", "azureendpoint":
			if v, ok := value.(string); ok {
				cm.config.AzureEndpoint = v
			}
		case "azure_api_version", "azureapiversion":
			if v, ok := value.(string); ok {
				cm.config.AzureAPIVersion = v
			}
		case "azure_deployment", "azuredeployment":
			if v, ok := value.(string); ok {
				cm.config.AzureDeployment = v
			}
		}
	}
	
	return cm.SaveConfig()
}

// GetConfigPath returns the configuration file path
func (cm *ConfigManager) GetConfigPath() string {
	return cm.configPath
}

// ValidateAPIKey performs a simple validation of the API key format
func ValidateAPIKey(apiKey string) error {
	apiKey = strings.TrimSpace(apiKey)
	
	if apiKey == "" {
		return fmt.Errorf("API key cannot be empty")
	}
	
	if len(apiKey) < 20 {
		return fmt.Errorf("API key appears to be too short")
	}
	
	// Check for common patterns
	if strings.HasPrefix(apiKey, "sk-") || strings.HasPrefix(apiKey, "claude-") {
		// OpenAI/Anthropic style key
		return nil
	}
	
	// Warn but don't fail for unknown patterns (could be Azure OpenAI)
	return nil
}

// GetProviderDefaults returns default configuration for a provider
func GetProviderDefaults(provider string) *AIConfig {
	switch provider {
	case "azure-openai":
		return &AIConfig{
			Provider:         "azure-openai",
			AzureAPIVersion:  "2024-02-15-preview",
			Model:           "gpt-4",
			MaxTokens:       4096,
			Timeout:         60,
		}
	case "anthropic":
		fallthrough
	default:
		return &AIConfig{
			Provider:  "anthropic",
			BaseURL:   "https://api.anthropic.com/v1",
			Model:     "claude-3-sonnet-20240229",
			MaxTokens: 4096,
			Timeout:   60,
		}
	}
}