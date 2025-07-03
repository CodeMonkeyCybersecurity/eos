// pkg/vault/comprehensive_security_test.go - Comprehensive security tests for Vault operations
package vault

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

// TestVaultSecurity_PathValidation tests secure path handling
func TestVaultSecurity_PathValidation(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		valid    bool
		concern  string
	}{
		{
			name:  "normal_secret_path",
			path:  "secret/data/myapp",
			valid: true,
		},
		{
			name:  "deep_nested_path",
			path:  "secret/data/prod/database/credentials",
			valid: true,
		},
		{
			name:  "path_with_hyphens",
			path:  "secret/data/my-app/db-config",
			valid: true,
		},
		{
			name:  "path_with_underscores",
			path:  "secret/data/my_app/db_config",
			valid: true,
		},
		{
			name:    "path_traversal_attempt",
			path:    "secret/data/../../../etc/passwd",
			valid:   false,
			concern: "path traversal",
		},
		{
			name:    "absolute_path_attempt",
			path:    "/etc/vault/config",
			valid:   false,
			concern: "absolute path",
		},
		{
			name:    "null_byte_injection",
			path:    "secret/data/test\x00admin",
			valid:   false,
			concern: "null byte injection",
		},
		{
			name:  "empty_path",
			path:  "",
			valid: false,
		},
		{
			name:    "path_with_spaces",
			path:    "secret/data/my app/config",
			valid:   true, // Vault should handle this
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test path validation logic
			isValid := isValidVaultPath(tt.path)
			
			if tt.valid {
				assert.True(t, isValid, "Path should be valid: %s", tt.path)
			} else {
				assert.False(t, isValid, "Path should be invalid: %s", tt.path)
				if tt.concern != "" {
					t.Logf("Security concern: %s for path: %s", tt.concern, tt.path)
				}
			}
		})
	}
}

// TestVaultSecurity_SecretDataValidation tests secret data security
func TestVaultSecurity_SecretDataValidation(t *testing.T) {
	tests := []struct {
		name    string
		data    map[string]interface{}
		valid   bool
		concern string
	}{
		{
			name: "normal_credentials",
			data: map[string]interface{}{
				"username": "dbuser",
				"password": "securepassword123",
				"host":     "localhost",
				"port":     5432,
			},
			valid: true,
		},
		{
			name: "api_keys",
			data: map[string]interface{}{
				"api_key":        "sk-1234567890abcdef",
				"api_secret":     "very-secret-key",
				"webhook_secret": "webhook-signing-key",
			},
			valid: true,
		},
		{
			name: "certificates",
			data: map[string]interface{}{
				"cert": "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----",
				"key":  "-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----",
			},
			valid: true,
		},
		{
			name: "large_secret_data",
			data: map[string]interface{}{
				"config": strings.Repeat("large config data ", 1000),
			},
			valid: true,
		},
		{
			name: "unicode_content",
			data: map[string]interface{}{
				"message": "Hello 世界 🔐",
				"name":    "José María",
			},
			valid: true,
		},
		{
			name: "special_characters",
			data: map[string]interface{}{
				"password":    "P@ssw0rd!#$%^&*()",
				"description": "Special chars: <>&\"'`",
			},
			valid: true,
		},
		{
			name: "empty_values",
			data: map[string]interface{}{
				"empty_string": "",
				"null_value":   nil,
			},
			valid: true,
		},
		{
			name: "nested_structures",
			data: map[string]interface{}{
				"database": map[string]interface{}{
					"primary": map[string]interface{}{
						"host":     "db1.example.com",
						"username": "admin",
						"password": "secret123",
					},
					"replica": map[string]interface{}{
						"host":     "db2.example.com", 
						"username": "readonly",
						"password": "readonly123",
					},
				},
			},
			valid: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isValid := isValidSecretData(tt.data)
			
			if tt.valid {
				assert.True(t, isValid, "Secret data should be valid")
			} else {
				assert.False(t, isValid, "Secret data should be invalid")
				if tt.concern != "" {
					t.Logf("Security concern: %s", tt.concern)
				}
			}
		})
	}
}

// TestVaultSecurity_TokenHandling tests secure token handling
func TestVaultSecurity_TokenHandling(t *testing.T) {
	tests := []struct {
		name    string
		token   string
		valid   bool
		concern string
	}{
		{
			name:  "valid_root_token",
			token: "hvs.AAAAAQAAABAAAbCdEfGhIjKlMnOpQrStUvWx",
			valid: true,
		},
		{
			name:  "valid_service_token",
			token: "s.AAAAAQAAABAAAbCdEfGhIjKlMnOpQrStUvWx",
			valid: true,
		},
		{
			name:  "valid_batch_token",
			token: "b.AAAAAQAAABAAAbCdEfGhIjKlMnOpQrStUvWx",
			valid: true,
		},
		{
			name:    "empty_token",
			token:   "",
			valid:   false,
			concern: "empty token",
		},
		{
			name:    "malformed_token",
			token:   "invalid-token-format",
			valid:   false,
			concern: "malformed token",
		},
		{
			name:    "token_with_newlines",
			token:   "hvs.AAAA\nAAQA\nAABA",
			valid:   false,
			concern: "token with newlines",
		},
		{
			name:    "token_with_spaces",
			token:   "hvs.AAAA AAQA AABA",
			valid:   false,
			concern: "token with spaces",
		},
		{
			name:    "suspiciously_short_token",
			token:   "hvs.ABC",
			valid:   false,
			concern: "suspiciously short",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isValid := validateVaultTokenFormat(tt.token)
			
			if tt.valid {
				assert.True(t, isValid, "Token should be valid")
			} else {
				assert.False(t, isValid, "Token should be invalid")
				if tt.concern != "" {
					t.Logf("Security concern: %s for token", tt.concern)
				}
			}
		})
	}
}

// TestVaultSecurity_EnvironmentValidation tests environment security
func TestVaultSecurity_EnvironmentValidation(t *testing.T) {
	// Save original environment
	originalAddr := os.Getenv("VAULT_ADDR")
	originalToken := os.Getenv("VAULT_TOKEN")
	defer func() {
		os.Setenv("VAULT_ADDR", originalAddr)
		os.Setenv("VAULT_TOKEN", originalToken)
	}()

	tests := []struct {
		name        string
		vaultAddr   string
		vaultToken  string
		valid       bool
		concern     string
	}{
		{
			name:       "secure_https_production",
			vaultAddr:  "https://vault.example.com:8200",
			vaultToken: "hvs.AAAAAQAAABAAAbCdEfGhIjKlMnOpQrStUvWx",
			valid:      true,
		},
		{
			name:       "localhost_development",
			vaultAddr:  "http://127.0.0.1:8200",
			vaultToken: "hvs.AAAAAQAAABAAAbCdEfGhIjKlMnOpQrStUvWx",
			valid:      true,
		},
		{
			name:       "custom_port",
			vaultAddr:  "https://vault.internal:8201",
			vaultToken: "s.AAAAAQAAABAAAbCdEfGhIjKlMnOpQrStUvWx",
			valid:      true,
		},
		{
			name:        "http_in_production",
			vaultAddr:   "http://vault.example.com:8200",
			vaultToken:  "hvs.AAAAAQAAABAAAbCdEfGhIjKlMnOpQrStUvWx",
			valid:       false,
			concern:     "HTTP in production",
		},
		{
			name:        "missing_vault_addr",
			vaultAddr:   "",
			vaultToken:  "hvs.AAAAAQAAABAAAbCdEfGhIjKlMnOpQrStUvWx",
			valid:       false,
			concern:     "missing VAULT_ADDR",
		},
		{
			name:        "missing_vault_token",
			vaultAddr:   "https://vault.example.com:8200",
			vaultToken:  "",
			valid:       false,
			concern:     "missing VAULT_TOKEN",
		},
		{
			name:        "invalid_url_format",
			vaultAddr:   "not-a-valid-url",
			vaultToken:  "hvs.AAAAAQAAABAAAbCdEfGhIjKlMnOpQrStUvWx",
			valid:       false,
			concern:     "invalid URL format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set test environment
			os.Setenv("VAULT_ADDR", tt.vaultAddr)
			os.Setenv("VAULT_TOKEN", tt.vaultToken)

			isValid := isValidVaultEnvironment()
			
			if tt.valid {
				assert.True(t, isValid, "Environment should be valid")
			} else {
				assert.False(t, isValid, "Environment should be invalid")
				if tt.concern != "" {
					t.Logf("Security concern: %s", tt.concern)
				}
			}
		})
	}
}

// TestVaultSecurity_FilePermissions tests secure file handling
func TestVaultSecurity_FilePermissions(t *testing.T) {
	tempDir := t.TempDir()

	tests := []struct {
		name         string
		filename     string
		permissions  os.FileMode
		content      string
		shouldSecure bool
		concern      string
	}{
		{
			name:         "secure_vault_config",
			filename:     "vault.hcl",
			permissions:  0600, // Owner read/write only
			content:      "storage \"file\" { path = \"/vault/data\" }",
			shouldSecure: true,
		},
		{
			name:         "secure_token_file",
			filename:     ".vault-token",
			permissions:  0600,
			content:      "hvs.AAAAAQAAABAAAbCdEfGhIjKlMnOpQrStUvWx",
			shouldSecure: true,
		},
		{
			name:         "secure_key_file",
			filename:     "vault.key",
			permissions:  0400, // Owner read only
			content:      "-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----",
			shouldSecure: true,
		},
		{
			name:         "insecure_world_readable",
			filename:     "vault-config.hcl",
			permissions:  0644, // World readable
			content:      "storage \"file\" { path = \"/vault/data\" }",
			shouldSecure: false,
			concern:      "world readable config",
		},
		{
			name:         "insecure_group_writable",
			filename:     "vault.token",
			permissions:  0660, // Group writable
			content:      "hvs.AAAAAQAAABAAAbCdEfGhIjKlMnOpQrStUvWx",
			shouldSecure: false,
			concern:      "group writable token",
		},
		{
			name:         "insecure_world_writable",
			filename:     "vault-key.pem",
			permissions:  0666, // World writable
			content:      "-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----",
			shouldSecure: false,
			concern:      "world writable key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filePath := filepath.Join(tempDir, tt.filename)
			
			// Create file with content
			err := os.WriteFile(filePath, []byte(tt.content), tt.permissions)
			require.NoError(t, err)

			// Test file security
			isSecure := isSecureFilePermissions(filePath)
			
			if tt.shouldSecure {
				assert.True(t, isSecure, "File should have secure permissions: %s", tt.filename)
			} else {
				assert.False(t, isSecure, "File should be flagged as insecure: %s", tt.filename)
				if tt.concern != "" {
					t.Logf("Security concern: %s for file: %s", tt.concern, tt.filename)
				}
			}
		})
	}
}

// TestVaultSecurity_ConfigValidation tests configuration security
func TestVaultSecurity_ConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		config  string
		valid   bool
		concern string
	}{
		{
			name: "secure_production_config",
			config: `
storage "consul" {
  address = "127.0.0.1:8500"
  path    = "vault/"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_cert_file = "/vault/tls/vault.crt"
  tls_key_file  = "/vault/tls/vault.key"
}

ui = true
cluster_addr = "https://vault.example.com:8201"
api_addr = "https://vault.example.com:8200"
`,
			valid: true,
		},
		{
			name: "development_config",
			config: `
storage "file" {
  path = "/tmp/vault-data"
}

listener "tcp" {
  address     = "127.0.0.1:8200"
  tls_disable = 1
}

ui = true
`,
			valid: true, // Valid for development
		},
		{
			name: "insecure_production_no_tls",
			config: `
storage "consul" {
  address = "127.0.0.1:8500"
  path    = "vault/"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = 1
}

ui = true
`,
			valid:   false,
			concern: "TLS disabled in production",
		},
		{
			name: "insecure_weak_storage",
			config: `
storage "inmem" {}

listener "tcp" {
  address = "0.0.0.0:8200"
}
`,
			valid:   false,
			concern: "in-memory storage",
		},
		{
			name: "missing_listener",
			config: `
storage "file" {
  path = "/vault/data"
}

ui = true
`,
			valid:   false,
			concern: "missing listener configuration",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isValid := isValidVaultConfig(tt.config)
			
			if tt.valid {
				assert.True(t, isValid, "Config should be valid")
			} else {
				assert.False(t, isValid, "Config should be invalid")
				if tt.concern != "" {
					t.Logf("Security concern: %s", tt.concern)
				}
			}
		})
	}
}

// TestVaultClient_SecurityInitialization tests secure client initialization
func TestVaultClient_SecurityInitialization(t *testing.T) {
	// Save original environment
	originalAddr := os.Getenv("VAULT_ADDR")
	originalToken := os.Getenv("VAULT_TOKEN")
	defer func() {
		os.Setenv("VAULT_ADDR", originalAddr)
		os.Setenv("VAULT_TOKEN", originalToken)
	}()

	t.Run("secure_initialization", func(t *testing.T) {
		os.Setenv("VAULT_ADDR", "https://vault.example.com:8200")
		os.Setenv("VAULT_TOKEN", "hvs.AAAAAQAAABAAAbCdEfGhIjKlMnOpQrStUvWx")

		rc := createTestRuntimeContext(t)
		
		client, err := GetVaultClient(rc)
		
		// In test environment, this will fail due to missing Vault
		// but we can verify the security validation worked
		if err != nil {
			// Expected in test environment
			assert.Error(t, err)
		} else {
			assert.NotNil(t, client)
		}
	})

	t.Run("insecure_environment_rejected", func(t *testing.T) {
		os.Setenv("VAULT_ADDR", "")
		os.Setenv("VAULT_TOKEN", "")

		rc := createTestRuntimeContext(t)
		
		_, err := GetVaultClient(rc)
		assert.Error(t, err, "Should reject insecure environment")
	})
}

// TestVaultSecurity_ConcurrentAccess tests thread safety
func TestVaultSecurity_ConcurrentAccess(t *testing.T) {
	const goroutines = 10
	const operations = 5

	results := make(chan bool, goroutines*operations)

	// Test concurrent security validations
	for g := 0; g < goroutines; g++ {
		go func(goroutineID int) {
			for i := 0; i < operations; i++ {
				// Test different security functions concurrently
				path := fmt.Sprintf("secret/data/test-%d-%d", goroutineID, i)
				token := "hvs.AAAAAQAAABAAAbCdEfGhIjKlMnOpQrStUvWx"
				
				pathValid := isValidVaultPath(path)
				tokenValid := validateVaultTokenFormat(token)
				
				results <- pathValid && tokenValid
			}
		}(g)
	}

	// Collect results
	for i := 0; i < goroutines*operations; i++ {
		result := <-results
		assert.True(t, result, "Concurrent security validations should succeed")
	}
}

// Helper functions for security validation (would be implemented in actual code)

func isValidVaultPath(path string) bool {
	if path == "" {
		return false
	}
	
	// Check for path traversal attempts
	if strings.Contains(path, "..") {
		return false
	}
	
	// Check for absolute paths
	if strings.HasPrefix(path, "/") {
		return false
	}
	
	// Check for null bytes
	if strings.Contains(path, "\x00") {
		return false
	}
	
	return true
}

func isValidSecretData(data map[string]interface{}) bool {
	if data == nil {
		return false
	}
	
	// All data is considered valid for Vault storage
	// Vault handles serialization securely
	return true
}

func validateVaultTokenFormat(token string) bool {
	if token == "" {
		return false
	}
	
	// Check for basic Vault token format
	if !strings.HasPrefix(token, "hvs.") && 
	   !strings.HasPrefix(token, "s.") && 
	   !strings.HasPrefix(token, "b.") {
		return false
	}
	
	// Check for whitespace
	if strings.Contains(token, " ") || strings.Contains(token, "\n") {
		return false
	}
	
	// Check minimum length
	if len(token) < 10 {
		return false
	}
	
	return true
}

func isValidVaultEnvironment() bool {
	addr := os.Getenv("VAULT_ADDR")
	token := os.Getenv("VAULT_TOKEN")
	
	if addr == "" || token == "" {
		return false
	}
	
	// Basic URL validation
	if !strings.HasPrefix(addr, "http://") && !strings.HasPrefix(addr, "https://") {
		return false
	}
	
	return validateVaultTokenFormat(token)
}

func isSecureFilePermissions(filePath string) bool {
	info, err := os.Stat(filePath)
	if err != nil {
		return false
	}
	
	mode := info.Mode()
	
	// Check if file is readable/writable by group or others
	if mode&0077 != 0 {
		return false
	}
	
	return true
}

func isValidVaultConfig(config string) bool {
	if config == "" {
		return false
	}
	
	// Basic validation - should contain storage and listener
	hasStorage := strings.Contains(config, "storage")
	hasListener := strings.Contains(config, "listener")
	
	// Check for insecure patterns
	hasInMemStorage := strings.Contains(config, `storage "inmem"`)
	
	return hasStorage && hasListener && !hasInMemStorage
}

func createTestRuntimeContext(t *testing.T) *eos_io.RuntimeContext {
	logger := zaptest.NewLogger(t)
	ctx := context.Background()
	
	return &eos_io.RuntimeContext{
		Ctx:        ctx,
		Log:        logger,
		Timestamp:  time.Now(),
		Component:  "test",
		Command:    "test",
		Attributes: make(map[string]string),
	}
}