// pkg/ai/config.go

package ai

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
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
	AzureEndpoint   string `yaml:"azure_endpoint,omitempty"`
	AzureAPIVersion string `yaml:"azure_api_version,omitempty"`
	AzureDeployment string `yaml:"azure_deployment,omitempty"`

	ActionSecurity ActionSecurityConfig `yaml:"action_security,omitempty"`
	DataSharing    DataSharingConfig    `yaml:"data_sharing,omitempty"`
	PolicySecrets  []string             `yaml:"policy_secrets,omitempty"`
}

// ActionSecurityConfig controls AI action execution guardrails
type ActionSecurityConfig struct {
	WorkspaceAllowlist []string `yaml:"workspace_allowlist,omitempty"`
	AllowedCommands    []string `yaml:"allowed_commands,omitempty"`
	DeniedArguments    []string `yaml:"denied_arguments,omitempty"`
	MaxArguments       int      `yaml:"max_arguments,omitempty"`
	MaxCommandLength   int      `yaml:"max_command_length,omitempty"`
}

// DataSharingConfig controls how much context is shared with AI providers
type DataSharingConfig struct {
	IncludeSecretFiles bool  `yaml:"include_secret_files,omitempty"`
	RedactSensitive    *bool `yaml:"redact_sensitive,omitempty"`
	RequireConsent     *bool `yaml:"require_consent,omitempty"`
}

// ConfigManager manages AI configuration
type ConfigManager struct {
	configPath string
	config     *AIConfig
}

const (
	defaultMaxArguments     = 12
	defaultMaxCommandLength = 512
)

func (cfg *AIConfig) applyDefaults() {
	if cfg.Provider == "" {
		cfg.Provider = "anthropic"
	}
	if cfg.BaseURL == "" {
		cfg.BaseURL = "https://api.anthropic.com/v1"
	}
	if cfg.Model == "" {
		cfg.Model = "claude-3-sonnet-20240229"
	}
	if cfg.MaxTokens == 0 {
		cfg.MaxTokens = 4096
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 60
	}
	cfg.ActionSecurity.applyDefaults()
	cfg.DataSharing.applyDefaults()
}

func (cfg *ActionSecurityConfig) applyDefaults() {
	if cfg.AllowedCommands == nil || len(cfg.AllowedCommands) == 0 {
		cfg.AllowedCommands = append([]string{}, defaultAllowedCommands...)
	}
	if cfg.DeniedArguments == nil || len(cfg.DeniedArguments) == 0 {
		cfg.DeniedArguments = append([]string{}, defaultDeniedArguments...)
	}
	if cfg.MaxArguments == 0 {
		cfg.MaxArguments = defaultMaxArguments
	}
	if cfg.MaxCommandLength == 0 {
		cfg.MaxCommandLength = defaultMaxCommandLength
	}
}

func (cfg *DataSharingConfig) applyDefaults() {
	if cfg.RedactSensitive == nil {
		defaultTrue := true
		cfg.RedactSensitive = &defaultTrue
	}
	if cfg.RequireConsent == nil {
		defaultTrue := true
		cfg.RequireConsent = &defaultTrue
	}
}

// NewConfigManager creates a new configuration manager
func NewConfigManager() *ConfigManager {
	// Default config path in user's config directory
	configDir, err := os.UserConfigDir()
	if err != nil {
		configDir = os.Getenv("HOME")
	}

	configPath := filepath.Join(configDir, "eos", "ai-config.yaml")

	cm := &ConfigManager{
		configPath: configPath,
		config:     &AIConfig{},
	}
	cm.config.applyDefaults()
	return cm
}

// LoadConfig loads the AI configuration from file
func (cm *ConfigManager) LoadConfig() error {
	// Ensure config directory exists
	configDir := filepath.Dir(cm.configPath)
	if err := os.MkdirAll(configDir, shared.SecretDirPerm); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Check if config file exists
	if _, err := os.Stat(cm.configPath); os.IsNotExist(err) {
		cm.config = &AIConfig{}
		cm.config.applyDefaults()
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
	cm.config.applyDefaults()

	return nil
}

// SaveConfig saves the AI configuration to file
func (cm *ConfigManager) SaveConfig() error {
	// Ensure config directory exists
	configDir := filepath.Dir(cm.configPath)
	if err := os.MkdirAll(configDir, shared.SecretDirPerm); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Marshal to YAML
	data, err := yaml.Marshal(cm.config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	// Write to file with restricted permissions
	if err := os.WriteFile(cm.configPath, data, shared.SecretFilePerm); err != nil {
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

		// Get Vault address
		vaultAddr := shared.GetVaultAddrWithEnv()

		// Try to get secret from Vault
		vaultClient, err := vault.NewClient(vaultAddr, logger.Logger().Logger)
		if err != nil {
			logger.Debug("Failed to create Vault client", zap.Error(err))
		} else {
			secret, err := vaultClient.GetSecret(rc.Ctx, cm.config.APIKeyVault)
			if err == nil && secret != nil && secret.Data != nil {
				// Check for 'value' field first (standard convention)
				if apiKey, ok := secret.Data["value"].(string); ok && apiKey != "" {
					logger.Debug("Successfully retrieved API key from Vault")
					return apiKey, nil
				}
				// Check for 'api_key' field as fallback
				if apiKey, ok := secret.Data["api_key"].(string); ok && apiKey != "" {
					logger.Debug("Successfully retrieved API key from Vault")
					return apiKey, nil
				}
			}
			if err != nil {
				logger.Debug("Failed to retrieve API key from Vault", zap.Error(err))
			}
		}
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

// GetActionPolicy returns the execution policy applied to AI actions
func (cm *ConfigManager) GetActionPolicy(workingDir string) *ActionExecutionPolicy {
	policy := &ActionExecutionPolicy{}
	for _, workspace := range cm.config.ActionSecurity.WorkspaceAllowlist {
		if workspace == "" {
			continue
		}
		canonical := filepath.Clean(workspace)
		if abs, err := filepath.Abs(canonical); err == nil {
			canonical = abs
		}
		policy.WorkspaceAllowlist = append(policy.WorkspaceAllowlist, canonical)
	}
	policy.AllowedCommands = append(policy.AllowedCommands, cm.config.ActionSecurity.AllowedCommands...)
	policy.DeniedArguments = append(policy.DeniedArguments, cm.config.ActionSecurity.DeniedArguments...)
	policy.MaxArguments = cm.config.ActionSecurity.MaxArguments
	policy.MaxCommandLength = cm.config.ActionSecurity.MaxCommandLength
	if len(policy.AllowedCommands) == 0 {
		policy.AllowedCommands = append(policy.AllowedCommands, defaultAllowedCommands...)
	}
	if len(policy.DeniedArguments) == 0 {
		policy.DeniedArguments = append(policy.DeniedArguments, defaultDeniedArguments...)
	}
	if policy.MaxArguments == 0 {
		policy.MaxArguments = defaultMaxArguments
	}
	if policy.MaxCommandLength == 0 {
		policy.MaxCommandLength = defaultMaxCommandLength
	}

	if len(policy.WorkspaceAllowlist) == 0 {
		canonical := filepath.Clean(workingDir)
		if abs, err := filepath.Abs(canonical); err == nil {
			canonical = abs
		}
		policy.WorkspaceAllowlist = append(policy.WorkspaceAllowlist, canonical)
	} else {
		seen := false
		for _, allowed := range policy.WorkspaceAllowlist {
			if allowed == workingDir {
				seen = true
				break
			}
		}
		if !seen {
			canonical := filepath.Clean(workingDir)
			if abs, err := filepath.Abs(canonical); err == nil {
				canonical = abs
			}
			policy.WorkspaceAllowlist = append(policy.WorkspaceAllowlist, canonical)
		}
	}

	return policy
}

// BuildActionPolicy derives the execution policy from an AIConfig without reloading from disk
func BuildActionPolicy(cfg *AIConfig, workingDir string) *ActionExecutionPolicy {
	if cfg == nil {
		cfg = &AIConfig{}
	}
	cfg.applyDefaults()
	cm := &ConfigManager{configPath: "", config: cfg}
	return cm.GetActionPolicy(workingDir)
}

// IncludeSecretFiles returns whether environment scans should read secret-like files
func (cm *ConfigManager) IncludeSecretFiles() bool {
	return cm.config.DataSharing.IncludeSecretFiles
}

// RedactSensitive returns whether sensitive tokens should be redacted from prompts
func (cm *ConfigManager) RedactSensitive() bool {
	if cm.config.DataSharing.RedactSensitive == nil {
		return true
	}
	return *cm.config.DataSharing.RedactSensitive
}

// ConsentRequired returns whether operator consent is required before data sharing
func (cm *ConfigManager) ConsentRequired() bool {
	if cm.config.DataSharing.RequireConsent == nil {
		return true
	}
	return *cm.config.DataSharing.RequireConsent
}

// IncludeSecretFilesEnabled returns whether secret-like files may be analyzed
func (cfg *AIConfig) IncludeSecretFilesEnabled() bool {
	if cfg == nil {
		return false
	}
	return cfg.DataSharing.IncludeSecretFiles
}

// RedactionEnabled reports if sensitive values should be redacted before sharing
func (cfg *AIConfig) RedactionEnabled() bool {
	if cfg == nil {
		return true
	}
	if cfg.DataSharing.RedactSensitive == nil {
		return true
	}
	return *cfg.DataSharing.RedactSensitive
}

// ConsentPromptEnabled determines if the CLI must prompt before sharing context
func (cfg *AIConfig) ConsentPromptEnabled() bool {
	if cfg == nil {
		return true
	}
	if cfg.DataSharing.RequireConsent == nil {
		return true
	}
	return *cfg.DataSharing.RequireConsent
}

// PolicySecrets returns decoded signing keys for automation policy validation
func (cm *ConfigManager) PolicySecrets() [][]byte {
	var secrets [][]byte
	for _, entry := range cm.config.PolicySecrets {
		if decoded, err := hex.DecodeString(strings.TrimSpace(entry)); err == nil && len(decoded) > 0 {
			secrets = append(secrets, decoded)
		}
	}
	if env := strings.TrimSpace(os.Getenv("EOS_AUTOFIX_POLICY_SECRET")); env != "" {
		if decoded, err := hex.DecodeString(env); err == nil && len(decoded) > 0 {
			secrets = append(secrets, decoded)
		}
	}
	return secrets
}

// PolicySecretBytes decodes configured signing secrets for auto-fix policies
func (cfg *AIConfig) PolicySecretBytes() [][]byte {
	if cfg == nil {
		return nil
	}
	var secrets [][]byte
	for _, entry := range cfg.PolicySecrets {
		if decoded, err := hex.DecodeString(strings.TrimSpace(entry)); err == nil && len(decoded) > 0 {
			secrets = append(secrets, decoded)
		}
	}
	if env := strings.TrimSpace(os.Getenv("EOS_AUTOFIX_POLICY_SECRET")); env != "" {
		if decoded, err := hex.DecodeString(env); err == nil && len(decoded) > 0 {
			secrets = append(secrets, decoded)
		}
	}
	return secrets
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
			Provider:        "azure-openai",
			AzureAPIVersion: "2024-02-15-preview",
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

// Helper functions

func ContainsTechnicalTerms(text string) bool {
	technicalTerms := []string{
		"docker", "compose", "container", "terraform", "vault", "consul",
		"k3s", "kubernetes", "service", "config", "log", "error", "fail",
		"port", "network", "ssl", "tls", "certificate", "nginx", "apache",
	}

	lowText := strings.ToLower(text)
	for _, term := range technicalTerms {
		if strings.Contains(lowText, term) {
			return true
		}
	}
	return false
}

func DisplayEnvironmentAnalysis(env *EnvironmentContext, detailed bool) {
	fmt.Println(" Environment Analysis Results")
	fmt.Println(strings.Repeat("-", 40))

	// File System Analysis
	if env.FileSystem != nil {
		fs := env.FileSystem
		fmt.Printf(" Files Found:\n")
		if len(fs.ComposeFiles) > 0 {
			fmt.Printf("    Docker Compose: %d files\n", len(fs.ComposeFiles))
			if detailed {
				for _, file := range fs.ComposeFiles {
					fmt.Printf("      - %s (modified: %s)\n", file.Path, file.ModTime.Format("2006-01-02 15:04"))
				}
			}
		}
		if len(fs.TerraformFiles) > 0 {
			fmt.Printf("     Terraform: %d files\n", len(fs.TerraformFiles))
			if detailed {
				for _, file := range fs.TerraformFiles {
					fmt.Printf("      - %s\n", file.Path)
				}
			}
		}
		if len(fs.ConfigFiles) > 0 {
			fmt.Printf("     Configuration: %d files\n", len(fs.ConfigFiles))
		}
		fmt.Println()
	}

	// Services Analysis
	if env.Services != nil {
		services := env.Services
		fmt.Printf(" Services:\n")
		if len(services.DockerContainers) > 0 {
			fmt.Printf("    Docker Containers: %d\n", len(services.DockerContainers))
			if detailed {
				for _, container := range services.DockerContainers {
					fmt.Printf("      - %s: %s (%s)\n", container.Name, container.Status, container.Image)
				}
			}
		}
		if len(services.SystemdServices) > 0 {
			fmt.Printf("     Systemd Services: %d\n", len(services.SystemdServices))
		}
		if len(services.NetworkPorts) > 0 {
			fmt.Printf("    Listening Ports: %d\n", len(services.NetworkPorts))
		}
		fmt.Println()
	}

	// Infrastructure Status
	if env.Infrastructure != nil {
		infra := env.Infrastructure
		fmt.Printf("  Infrastructure:\n")
		if infra.VaultStatus != nil {
			status := " Unavailable"
			if infra.VaultStatus.Initialized {
				if infra.VaultStatus.Sealed {
					status = " Sealed"
				} else {
					status = " Ready"
				}
			}
			fmt.Printf("    Vault: %s\n", status)
		}
		if infra.ConsulStatus != nil && infra.ConsulStatus.Leader != "" {
			fmt.Printf("    Consul:  Ready (leader: %s)\n", infra.ConsulStatus.Leader)
		}
		fmt.Println()
	}

	// Recent Issues
	if env.Logs != nil && len(env.Logs.ErrorLogs) > 0 {
		fmt.Printf(" Recent Issues: %d errors found\n", len(env.Logs.ErrorLogs))
		if detailed {
			for i, log := range env.Logs.ErrorLogs {
				if i >= 5 {
					fmt.Printf("      ... and %d more\n", len(env.Logs.ErrorLogs)-5)
					break
				}
				fmt.Printf("      - [%s] %s\n", log.Service, log.Message[:min(80, len(log.Message))])
			}
		}
		fmt.Println()
	}
}

func StartInteractiveChat(rc *eos_io.RuntimeContext, assistant *AIAssistant, ctx *ConversationContext) error {
	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Print("You: ")
		input, err := reader.ReadString('\n')
		if err != nil {
			return err
		}

		input = strings.TrimSpace(input)
		if input == "" {
			continue
		}

		// Check for exit commands
		if strings.ToLower(input) == "exit" || strings.ToLower(input) == "quit" || strings.ToLower(input) == "bye" {
			fmt.Println(" Goodbye! Feel free to ask for help anytime.")
			break
		}

		// Special commands
		if strings.ToLower(input) == "analyze" {
			fmt.Println(" Re-analyzing environment...")
			analyzer := NewEnvironmentAnalyzer(ctx.Environment.WorkingDirectory)
			if env, err := analyzer.AnalyzeEnvironment(rc); err == nil {
				ctx.Environment = env
				fmt.Println(" Environment analysis updated.")
				continue
			}
		}

		fmt.Println(" Thinking...")

		// Get AI response
		response, err := assistant.Chat(rc, ctx, input)
		if err != nil {
			fmt.Printf(" Error: %v\n", err)
			continue
		}

		if len(response.Choices) == 0 {
			fmt.Println(" No response from AI")
			continue
		}

		fmt.Println("\n AI:")
		fmt.Println(response.Choices[0].Message.Content)
		fmt.Println()

		// Check for actions
		if actions, err := ParseActionsFromResponse(response.Choices[0].Message.Content); err == nil && len(actions) > 0 {
			fmt.Printf(" I have %d suggestion(s). Type 'implement' to execute them.\n\n", len(actions))
		}
	}

	return nil
}

func ImplementActions(rc *eos_io.RuntimeContext, actions []*Action, workingDir string, dryRun bool, policy *ActionExecutionPolicy) error {
	if len(actions) == 0 {
		fmt.Println("No actions to implement.")
		return nil
	}

	executor := NewActionExecutor(workingDir, dryRun, policy)

	fmt.Printf(" Implementing %d action(s)...\n\n", len(actions))

	for i, action := range actions {
		fmt.Printf("Action %d/%d: %s\n", i+1, len(actions), action.Description)

		result, err := executor.ExecuteAction(rc, action)
		if err != nil {
			fmt.Printf(" Failed: %v\n", err)
			continue
		}

		if result.Success {
			fmt.Printf(" Success: %s\n", result.Message)
			if result.Output != "" {
				fmt.Printf("   Output: %s\n", result.Output)
			}
		} else {
			fmt.Printf(" Failed: %s\n", result.Message)
		}
		fmt.Println()
	}

	return nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// maskAPIKey masks an API key for display purposes
func MaskAPIKey(apiKey string) string {
	if apiKey == "" {
		return "[not configured]"
	}

	// Show first few characters and last few characters
	if len(apiKey) > 10 {
		return apiKey[:6] + "..." + apiKey[len(apiKey)-4:]
	}

	// For shorter keys, just show partial
	if len(apiKey) > 4 {
		return apiKey[:3] + "..."
	}

	return "***"
}
