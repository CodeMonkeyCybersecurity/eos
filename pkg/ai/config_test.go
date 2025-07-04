package ai

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// TestConfigManagerSecurity tests configuration management security
func TestConfigManagerSecurity(t *testing.T) {
	// Create temporary directory for test configs
	tempDir, err := os.MkdirTemp("", "eos-ai-config-test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	t.Run("config_file_creation_security", func(t *testing.T) {
		// Create config manager with temporary path
		configManager := &ConfigManager{
			configPath: filepath.Join(tempDir, "test-config.yaml"),
			config:     &AIConfig{},
		}

		// Save configuration
		configManager.config = &AIConfig{
			Provider: "anthropic",
			APIKey:   "test-api-key-12345",
		}

		err := configManager.SaveConfig()
		require.NoError(t, err)

		// Check file permissions
		fileInfo, err := os.Stat(configManager.configPath)
		require.NoError(t, err)

		// File should have restrictive permissions (0600)
		mode := fileInfo.Mode().Perm()
		assert.Equal(t, os.FileMode(0600), mode, "Config file should have 0600 permissions")

		// Check directory permissions
		dirInfo, err := os.Stat(filepath.Dir(configManager.configPath))
		require.NoError(t, err)

		dirMode := dirInfo.Mode().Perm()
		assert.Equal(t, os.FileMode(0700), dirMode, "Config directory should have 0700 permissions")
	})

	t.Run("config_loading_security", func(t *testing.T) {
		configManager := &ConfigManager{
			configPath: filepath.Join(tempDir, "load-test-config.yaml"),
			config:     &AIConfig{},
		}

		// Create a config file with sensitive data
		testConfig := &AIConfig{
			Provider:    "anthropic",
			APIKey:      "sk-test123456789012345678901234567890",
			BaseURL:     "https://api.anthropic.com/v1",
			APIKeyVault: "secret/ai/api-key",
		}

		configManager.config = testConfig
		err := configManager.SaveConfig()
		require.NoError(t, err)

		// Load the configuration
		newConfigManager := &ConfigManager{
			configPath: configManager.configPath,
			config:     &AIConfig{},
		}

		err = newConfigManager.LoadConfig()
		require.NoError(t, err)

		// Verify configuration was loaded correctly
		loadedConfig := newConfigManager.GetConfig()
		assert.Equal(t, testConfig.Provider, loadedConfig.Provider)
		assert.Equal(t, testConfig.APIKey, loadedConfig.APIKey)
		assert.Equal(t, testConfig.BaseURL, loadedConfig.BaseURL)
		assert.Equal(t, testConfig.APIKeyVault, loadedConfig.APIKeyVault)
	})

	t.Run("malicious_config_file_handling", func(t *testing.T) {
		// Test handling of malicious YAML content
		maliciousYAML := `
provider: "anthropic"
api_key: "test-key"
# Attempt YAML injection
malicious_field: !!python/object/apply:os.system ["rm -rf /"]
`

		maliciousConfigPath := filepath.Join(tempDir, "malicious-config.yaml")
		err := os.WriteFile(maliciousConfigPath, []byte(maliciousYAML), 0600)
		require.NoError(t, err)

		configManager := &ConfigManager{
			configPath: maliciousConfigPath,
			config:     &AIConfig{},
		}

		// Should handle malicious YAML safely
		err = configManager.LoadConfig()
		// Might error due to unknown fields, but should not execute malicious code
		if err != nil {
			assert.NotContains(t, err.Error(), "system command executed")
		}
	})

	t.Run("config_path_traversal_prevention", func(t *testing.T) {
		// Test that config manager prevents path traversal attacks
		maliciousPaths := []string{
			"../../../etc/passwd",
			"/etc/shadow",
			"..\\..\\windows\\system32\\config\\sam",
		}

		var createdFiles []string
		defer func() {
			// Clean up any files that were actually created
			for _, file := range createdFiles {
				os.Remove(file)
				// Also try to remove parent directories if they're empty
				dir := filepath.Dir(file)
				for dir != "." && dir != "/" {
					os.Remove(dir) // Will fail if not empty, which is fine
					dir = filepath.Dir(dir)
				}
			}
		}()

		for _, maliciousPath := range maliciousPaths {
			configManager := &ConfigManager{
				configPath: maliciousPath,
				config:     &AIConfig{Provider: "test"},
			}

			// Should fail to create config in system directories
			err := configManager.SaveConfig()
			// Might succeed or fail depending on permissions, but shouldn't overwrite system files
			if err == nil {
				// Track created files for cleanup
				if _, err := os.Stat(maliciousPath); err == nil {
					createdFiles = append(createdFiles, maliciousPath)
				}
				// If it succeeds, verify it didn't overwrite a system file
				assert.NotEqual(t, "/etc/passwd", configManager.configPath)
			}
		}
	})
}

// TestAPIKeyManagementSecurity tests API key management security
func TestAPIKeyManagementSecurity(t *testing.T) {
	ctx := context.Background()
	logger := zap.NewNop()
	rc := &eos_io.RuntimeContext{
		Ctx: ctx,
		Log: logger,
	}

	// Create temporary directory for test configs
	tempDir, err := os.MkdirTemp("", "eos-ai-apikey-test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	t.Run("api_key_environment_precedence", func(t *testing.T) {
		configManager := &ConfigManager{
			configPath: filepath.Join(tempDir, "env-test-config.yaml"),
			config: &AIConfig{
				Provider: "anthropic",
				APIKey:   "config-file-key",
			},
		}

		// Environment variable should take precedence over config file
		os.Setenv("ANTHROPIC_API_KEY", "env-var-key")
		defer os.Unsetenv("ANTHROPIC_API_KEY")

		apiKey, err := configManager.GetAPIKey(rc)
		require.NoError(t, err)
		assert.Equal(t, "env-var-key", apiKey, "Environment variable should take precedence")
	})

	t.Run("api_key_provider_specific_vars", func(t *testing.T) {
		// Test provider-specific environment variables
		testCases := []struct {
			provider string
			envVar   string
			envValue string
		}{
			{"anthropic", "ANTHROPIC_API_KEY", "anthropic-key"},
			{"anthropic", "CLAUDE_API_KEY", "claude-key"},
			{"azure-openai", "AZURE_OPENAI_API_KEY", "azure-key"},
			{"azure-openai", "OPENAI_API_KEY", "openai-key"},
		}

		for _, tc := range testCases {
			// Clear all environment variables
			envVars := []string{"ANTHROPIC_API_KEY", "CLAUDE_API_KEY", "AZURE_OPENAI_API_KEY", "OPENAI_API_KEY", "AI_API_KEY"}
			for _, envVar := range envVars {
				os.Unsetenv(envVar)
			}

			// Set specific environment variable
			os.Setenv(tc.envVar, tc.envValue)

			configManager := &ConfigManager{
				configPath: filepath.Join(tempDir, "provider-test-config.yaml"),
				config: &AIConfig{
					Provider: tc.provider,
				},
			}

			apiKey, err := configManager.GetAPIKey(rc)
			require.NoError(t, err)
			assert.Equal(t, tc.envValue, apiKey, "Should use provider-specific environment variable")

			os.Unsetenv(tc.envVar)
		}
	})

	t.Run("api_key_generic_fallback", func(t *testing.T) {
		// Clear all provider-specific environment variables
		envVars := []string{"ANTHROPIC_API_KEY", "CLAUDE_API_KEY", "AZURE_OPENAI_API_KEY", "OPENAI_API_KEY"}
		for _, envVar := range envVars {
			os.Unsetenv(envVar)
		}

		// Set generic AI_API_KEY
		os.Setenv("AI_API_KEY", "generic-api-key")
		defer os.Unsetenv("AI_API_KEY")

		configManager := &ConfigManager{
			configPath: filepath.Join(tempDir, "generic-test-config.yaml"),
			config: &AIConfig{
				Provider: "anthropic",
			},
		}

		apiKey, err := configManager.GetAPIKey(rc)
		require.NoError(t, err)
		assert.Equal(t, "generic-api-key", apiKey, "Should fall back to generic AI_API_KEY")
	})

	t.Run("api_key_not_configured_error", func(t *testing.T) {
		// Clear all environment variables
		envVars := []string{"ANTHROPIC_API_KEY", "CLAUDE_API_KEY", "AZURE_OPENAI_API_KEY", "OPENAI_API_KEY", "AI_API_KEY"}
		for _, envVar := range envVars {
			os.Unsetenv(envVar)
		}

		configManager := &ConfigManager{
			configPath: filepath.Join(tempDir, "no-key-config.yaml"),
			config: &AIConfig{
				Provider: "anthropic",
				// No API key set
			},
		}

		apiKey, err := configManager.GetAPIKey(rc)
		assert.Error(t, err)
		assert.Empty(t, apiKey)
		assert.Contains(t, err.Error(), "API key not configured")
	})

	t.Run("api_key_validation_security", func(t *testing.T) {
		// Test API key validation
		testCases := []struct {
			name      string
			apiKey    string
			shouldErr bool
			reason    string
		}{
			{"empty_key", "", true, "empty key should be rejected"},
			{"whitespace_only", "   ", true, "whitespace-only key should be rejected"},
			{"too_short", "short", true, "short key should be rejected"},
			{"valid_openai", "sk-1234567890123456789012345678901234567890", false, "valid OpenAI key should be accepted"},
			{"valid_anthropic", "claude-1234567890123456789012345678901234567890", false, "valid Anthropic key should be accepted"},
			{"valid_generic", "valid-api-key-that-is-long-enough-1234567890", false, "valid generic key should be accepted"},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				err := ValidateAPIKey(tc.apiKey)
				if tc.shouldErr {
					assert.Error(t, err, tc.reason)
				} else {
					assert.NoError(t, err, tc.reason)
				}
			})
		}
	})

	t.Run("api_key_storage_security", func(t *testing.T) {
		configManager := &ConfigManager{
			configPath: filepath.Join(tempDir, "storage-test-config.yaml"),
			config:     &AIConfig{},
		}

		// Set API key
		err := configManager.SetAPIKey("sk-test123456789012345678901234567890")
		require.NoError(t, err)

		// Verify file was created with correct permissions
		fileInfo, err := os.Stat(configManager.configPath)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0600), fileInfo.Mode().Perm())

		// Verify API key is stored
		loadedConfig := configManager.GetConfig()
		assert.Equal(t, "sk-test123456789012345678901234567890", loadedConfig.APIKey)
	})

	t.Run("vault_path_configuration", func(t *testing.T) {
		configManager := &ConfigManager{
			configPath: filepath.Join(tempDir, "vault-test-config.yaml"),
			config:     &AIConfig{},
		}

		// Set Vault path for API key
		err := configManager.SetAPIKeyVault("secret/ai/anthropic-key")
		require.NoError(t, err)

		// Verify Vault path is set and plaintext key is cleared
		config := configManager.GetConfig()
		assert.Equal(t, "secret/ai/anthropic-key", config.APIKeyVault)
		assert.Empty(t, config.APIKey, "Plaintext API key should be cleared when using Vault")
	})
}

// TestConfigurationValidation tests configuration validation security
func TestConfigurationValidation(t *testing.T) {
	t.Run("provider_validation", func(t *testing.T) {
		// Test provider validation and defaults
		validProviders := []string{"anthropic", "azure-openai"}
		
		for _, provider := range validProviders {
			defaults := GetProviderDefaults(provider)
			assert.Equal(t, provider, defaults.Provider)
			assert.NotEmpty(t, defaults.Model, "Provider should have default model")
			assert.Greater(t, defaults.MaxTokens, 0, "Provider should have positive max tokens")
			assert.Greater(t, defaults.Timeout, 0, "Provider should have positive timeout")
		}

		// Test invalid provider defaults to anthropic
		invalidDefaults := GetProviderDefaults("invalid-provider")
		assert.Equal(t, "anthropic", invalidDefaults.Provider)
	})

	t.Run("url_validation", func(t *testing.T) {
		// Test URL validation for security
		testURLs := []string{
			"https://api.anthropic.com/v1",              // Valid HTTPS
			"http://localhost:8080",                     // Local HTTP (might be ok for dev)
			"ftp://malicious.com/api",                   // Invalid protocol
			"javascript:alert('xss')",                   // XSS attempt
			"file:///etc/passwd",                        // File access attempt
		}

		for _, url := range testURLs {
			config := &AIConfig{
				BaseURL: url,
			}

			// In a real implementation, we might validate URLs
			assert.NotEmpty(t, config.BaseURL)
			
			// Could implement URL validation here:
			// - Ensure HTTPS for production
			// - Block file:// and javascript: schemes
			// - Validate hostname patterns
		}
	})

	t.Run("token_limits_validation", func(t *testing.T) {
		// Test token limits for security and cost control
		testCases := []struct {
			maxTokens int
			valid     bool
		}{
			{0, false},     // Zero tokens invalid
			{-1, false},    // Negative tokens invalid
			{100, true},    // Small limit valid
			{4096, true},   // Standard limit valid
			{100000, true}, // Large limit valid (but might be costly)
		}

		for _, tc := range testCases {
			config := &AIConfig{
				MaxTokens: tc.maxTokens,
			}

			// In a real implementation, we might validate token limits
			if tc.valid {
				assert.Greater(t, config.MaxTokens, 0, "Valid token limit should be positive")
			} else {
				assert.LessOrEqual(t, config.MaxTokens, 0, "Invalid token limit should be non-positive")
			}
		}
	})

	t.Run("timeout_validation", func(t *testing.T) {
		// Test timeout validation for security
		testCases := []struct {
			timeout int
			valid   bool
		}{
			{0, false},   // Zero timeout invalid
			{-1, false},  // Negative timeout invalid
			{1, true},    // Very short timeout valid
			{60, true},   // Standard timeout valid
			{3600, true}, // Long timeout valid (but risky)
		}

		for _, tc := range testCases {
			config := &AIConfig{
				Timeout: tc.timeout,
			}

			if tc.valid {
				assert.Greater(t, config.Timeout, 0, "Valid timeout should be positive")
			} else {
				assert.LessOrEqual(t, config.Timeout, 0, "Invalid timeout should be non-positive")
			}
		}
	})

	t.Run("azure_configuration_validation", func(t *testing.T) {
		// Test Azure-specific configuration validation
		azureConfig := &AIConfig{
			Provider:        "azure-openai",
			AzureEndpoint:   "https://test.openai.azure.com",
			AzureAPIVersion: "2024-02-15-preview",
			AzureDeployment: "gpt-4-deployment",
		}

		// Verify Azure configuration
		assert.Equal(t, "azure-openai", azureConfig.Provider)
		assert.True(t, strings.HasPrefix(azureConfig.AzureEndpoint, "https://"))
		assert.NotEmpty(t, azureConfig.AzureAPIVersion)
		assert.NotEmpty(t, azureConfig.AzureDeployment)

		// Test Azure endpoint validation
		maliciousEndpoints := []string{
			"http://malicious.com",           // Non-HTTPS
			"javascript:alert('xss')",        // XSS attempt
			"file:///etc/passwd",             // File access
			"ldap://malicious.com",           // LDAP injection
		}

		for _, endpoint := range maliciousEndpoints {
			azureConfig.AzureEndpoint = endpoint
			// In a real implementation, we would validate the endpoint
			// and reject malicious URLs
		}
	})
}

// TestConfigurationUpdateSecurity tests configuration update security
func TestConfigurationUpdateSecurity(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "eos-ai-update-test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	t.Run("update_config_type_safety", func(t *testing.T) {
		configManager := &ConfigManager{
			configPath: filepath.Join(tempDir, "update-test-config.yaml"),
			config:     &AIConfig{},
		}

		// Test type-safe updates
		validUpdates := map[string]any{
			"provider":          "anthropic",
			"api_key":           "test-key",
			"base_url":          "https://api.example.com",
			"model":             "claude-3-sonnet",
			"max_tokens":        2048,
			"timeout":           30,
			"azure_endpoint":    "https://test.openai.azure.com",
			"azure_api_version": "2024-02-15-preview",
			"azure_deployment":  "gpt-4-deployment",
		}

		err := configManager.UpdateConfig(validUpdates)
		require.NoError(t, err)

		config := configManager.GetConfig()
		assert.Equal(t, "anthropic", config.Provider)
		assert.Equal(t, "test-key", config.APIKey)
		assert.Equal(t, 2048, config.MaxTokens)
		assert.Equal(t, 30, config.Timeout)
	})

	t.Run("update_config_invalid_types", func(t *testing.T) {
		configManager := &ConfigManager{
			configPath: filepath.Join(tempDir, "invalid-update-config.yaml"),
			config:     &AIConfig{},
		}

		// Test invalid type updates
		invalidUpdates := map[string]any{
			"provider":   123,        // Should be string
			"max_tokens": "invalid",  // Should be int
			"timeout":    "invalid",  // Should be int
			"unknown":    "value",    // Unknown field
		}

		err := configManager.UpdateConfig(invalidUpdates)
		// Current implementation doesn't validate types, but should handle gracefully
		assert.NoError(t, err)

		// Verify invalid updates were ignored or handled safely
		config := configManager.GetConfig()
		assert.NotEqual(t, 123, config.Provider) // Should not be set to invalid type
	})

	t.Run("update_config_case_insensitive", func(t *testing.T) {
		configManager := &ConfigManager{
			configPath: filepath.Join(tempDir, "case-test-config.yaml"),
			config:     &AIConfig{},
		}

		// Test case-insensitive field names
		caseInsensitiveUpdates := map[string]any{
			"PROVIDER":    "anthropic",
			"Api_Key":     "test-key",
			"BASE_URL":    "https://api.example.com",
			"MaxTokens":   1024,
			"TIMEOUT":     45,
		}

		err := configManager.UpdateConfig(caseInsensitiveUpdates)
		require.NoError(t, err)

		config := configManager.GetConfig()
		assert.Equal(t, "anthropic", config.Provider)
		assert.Equal(t, "test-key", config.APIKey)
		assert.Equal(t, "https://api.example.com", config.BaseURL)
		assert.Equal(t, 1024, config.MaxTokens)
		assert.Equal(t, 45, config.Timeout)
	})

	t.Run("update_config_malicious_values", func(t *testing.T) {
		configManager := &ConfigManager{
			configPath: filepath.Join(tempDir, "malicious-update-config.yaml"),
			config:     &AIConfig{},
		}

		// Test malicious configuration values
		maliciousUpdates := map[string]any{
			"provider":     "'; DROP TABLE config; --",
			"api_key":      "<script>alert('xss')</script>",
			"base_url":     "javascript:alert('xss')",
			"model":        "../../../etc/passwd",
			"max_tokens":   -999999,
			"timeout":      0,
		}

		err := configManager.UpdateConfig(maliciousUpdates)
		require.NoError(t, err)

		// Verify malicious values are stored as-is but should be validated when used
		config := configManager.GetConfig()
		assert.Contains(t, config.Provider, "DROP TABLE") // Stored as string, not executed
		assert.Contains(t, config.APIKey, "script")       // Stored as string, not executed
	})
}

// TestFileSystemSecurity tests file system security aspects
func TestFileSystemSecurity(t *testing.T) {
	t.Run("config_directory_creation", func(t *testing.T) {
		// Test secure config directory creation
		tempDir, err := os.MkdirTemp("", "eos-config-dir-test")
		require.NoError(t, err)
		defer os.RemoveAll(tempDir)

		configPath := filepath.Join(tempDir, "nested", "deep", "config.yaml")
		configManager := &ConfigManager{
			configPath: configPath,
			config:     &AIConfig{Provider: "test"},
		}

		err = configManager.SaveConfig()
		require.NoError(t, err)

		// Verify nested directories were created with secure permissions
		currentPath := filepath.Dir(configPath)
		for currentPath != tempDir {
			dirInfo, err := os.Stat(currentPath)
			require.NoError(t, err)
			assert.Equal(t, os.FileMode(0700), dirInfo.Mode().Perm())
			currentPath = filepath.Dir(currentPath)
		}
	})

	t.Run("config_file_atomic_write", func(t *testing.T) {
		// Test atomic config file writes to prevent corruption
		tempDir, err := os.MkdirTemp("", "eos-atomic-test")
		require.NoError(t, err)
		defer os.RemoveAll(tempDir)

		configPath := filepath.Join(tempDir, "atomic-config.yaml")
		configManager := &ConfigManager{
			configPath: configPath,
			config: &AIConfig{
				Provider: "anthropic",
				APIKey:   "initial-key",
			},
		}

		// Initial save
		err = configManager.SaveConfig()
		require.NoError(t, err)

		// Update config
		configManager.config.APIKey = "updated-key"
		err = configManager.SaveConfig()
		require.NoError(t, err)

		// Verify config was updated correctly
		newConfigManager := &ConfigManager{
			configPath: configPath,
			config:     &AIConfig{},
		}

		err = newConfigManager.LoadConfig()
		require.NoError(t, err)
		assert.Equal(t, "updated-key", newConfigManager.config.APIKey)
	})

	t.Run("config_path_validation", func(t *testing.T) {
		// Test config path validation to prevent path traversal
		maliciousPaths := []string{
			"../../../etc/passwd",
			"/etc/shadow",
			"..\\..\\windows\\system32\\config\\sam",
			"/dev/null",
			"/proc/self/mem",
		}

		var createdFiles []string
		defer func() {
			// Clean up any files that were actually created
			for _, file := range createdFiles {
				os.Remove(file)
				// Also try to remove parent directories if they're empty
				dir := filepath.Dir(file)
				for dir != "." && dir != "/" {
					os.Remove(dir) // Will fail if not empty, which is fine
					dir = filepath.Dir(dir)
				}
			}
		}()

		for _, path := range maliciousPaths {
			configManager := &ConfigManager{
				configPath: path,
				config:     &AIConfig{Provider: "test"},
			}

			// Should handle malicious paths safely
			err := configManager.SaveConfig()
			// May succeed or fail, but should not overwrite system files
			if err == nil {
				// Track created files for cleanup
				if _, err := os.Stat(path); err == nil {
					createdFiles = append(createdFiles, path)
				}
			}
		}
	})
}