// pkg/vault/config_validator_test.go

package vault

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
)

func TestValidateConfigWithFallback(t *testing.T) {
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	tests := []struct {
		name          string
		configContent string
		expectValid   bool
		expectErrors  int
		expectMethod  string // "vault-binary" or "manual-parser"
		description   string
	}{
		{
			name: "valid_basic_config",
			configContent: `
storage "file" {
  path = "/opt/vault/data"
}

listener "tcp" {
  address = "0.0.0.0:8179"
  tls_disable = false
  tls_cert_file = "/opt/vault/tls/vault.crt"
  tls_key_file = "/opt/vault/tls/vault.key"
}

api_addr = "https://shared.GetInternalHostname:8179"
cluster_addr = "https://shared.GetInternalHostname:8180"
ui = true
`,
			expectValid:  true,
			expectErrors: 0,
			description:  "Valid minimal Vault configuration should pass",
		},
		{
			name: "missing_storage_block",
			configContent: `
listener "tcp" {
  address = "0.0.0.0:8179"
  tls_disable = true
}

api_addr = "https://shared.GetInternalHostname:8179"
`,
			expectValid:  false,
			expectErrors: 1, // Missing storage block
			description:  "Config without storage block should fail",
		},
		{
			name: "missing_listener_block",
			configContent: `
storage "file" {
  path = "/opt/vault/data"
}

api_addr = "https://shared.GetInternalHostname:8179"
`,
			expectValid:  false,
			expectErrors: 1, // Missing listener block
			description:  "Config without listener block should fail",
		},
		{
			name: "tls_cert_without_key",
			configContent: `
storage "file" {
  path = "/opt/vault/data"
}

listener "tcp" {
  address = "0.0.0.0:8179"
  tls_disable = false
  tls_cert_file = "/opt/vault/tls/vault.crt"
}

api_addr = "https://shared.GetInternalHostname:8179"
`,
			expectValid:  false,
			expectErrors: 1, // tls_cert_file without tls_key_file
			description:  "TLS cert specified without key should fail",
		},
		{
			name: "invalid_hcl_syntax",
			configContent: `
storage "file" {
  path = "/opt/vault/data"
  # Missing closing brace

listener "tcp" {
  address = "0.0.0.0:8179"
}
`,
			expectValid:  false,
			expectErrors: 1, // HCL syntax error
			description:  "Invalid HCL syntax should fail",
		},
		{
			name: "legacy_port_8200",
			configContent: `
storage "file" {
  path = "/opt/vault/data"
}

listener "tcp" {
  address = "0.0.0.0:8200"
  tls_disable = true
}

api_addr = "http://shared.GetInternalHostname:8200"
`,
			expectValid:  true, // Valid but has warnings
			expectErrors: 0,
			description:  "Legacy port 8200 should generate warning but pass validation",
		},
		{
			name: "tls_disable_as_string",
			configContent: `
storage "file" {
  path = "/opt/vault/data"
}

listener "tcp" {
  address = "0.0.0.0:8179"
  tls_disable = "true"
}

api_addr = "http://shared.GetInternalHostname:8179"
`,
			expectValid:  true, // Valid but has warnings
			expectErrors: 0,
			description:  "tls_disable as string should generate warning",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary config file
			tmpDir := t.TempDir()
			configPath := filepath.Join(tmpDir, "vault.hcl")

			if err := os.WriteFile(configPath, []byte(tt.configContent), 0640); err != nil {
				t.Fatalf("Failed to write test config: %v", err)
			}

			// Run validation
			result, err := ValidateConfigWithFallback(rc, configPath)
			if err != nil && tt.expectValid {
				t.Errorf("Unexpected validation error: %v", err)
				return
			}

			// Check validity
			if result.Valid != tt.expectValid {
				t.Errorf("Expected valid=%v, got valid=%v", tt.expectValid, result.Valid)
				t.Logf("Errors: %v", result.Errors)
			}

			// Check error count
			if len(result.Errors) != tt.expectErrors {
				t.Errorf("Expected %d errors, got %d: %v",
					tt.expectErrors, len(result.Errors), result.Errors)
			}

			// Verify method is set
			if result.Method == "" {
				t.Error("Validation method should be set")
			}

			t.Logf("Validation method: %s", result.Method)
			t.Logf("Valid: %v, Errors: %d, Warnings: %d, Suggestions: %d",
				result.Valid, len(result.Errors), len(result.Warnings), len(result.Suggestions))
		})
	}
}

func TestAssessConfigFile(t *testing.T) {
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	tests := []struct {
		name        string
		setupFunc   func(string) string // Returns config path
		expectError bool
		description string
	}{
		{
			name: "file_exists_valid_perms",
			setupFunc: func(tmpDir string) string {
				path := filepath.Join(tmpDir, "vault.hcl")
				_ = os.WriteFile(path, []byte("storage \"file\" { path = \"/tmp\" }\n"), 0640)
				return path
			},
			expectError: false,
			description: "Valid config file should pass assessment",
		},
		{
			name: "file_not_exists",
			setupFunc: func(tmpDir string) string {
				return filepath.Join(tmpDir, "nonexistent.hcl")
			},
			expectError: true,
			description: "Non-existent file should fail assessment",
		},
		{
			name: "file_empty",
			setupFunc: func(tmpDir string) string {
				path := filepath.Join(tmpDir, "empty.hcl")
				_ = os.WriteFile(path, []byte(""), 0640)
				return path
			},
			expectError: true,
			description: "Empty config file should fail assessment",
		},
		{
			name: "file_world_writable",
			setupFunc: func(tmpDir string) string {
				path := filepath.Join(tmpDir, "vault.hcl")
				_ = os.WriteFile(path, []byte("storage \"file\" { path = \"/tmp\" }\n"), 0646)
				return path
			},
			expectError: false, // Warning but not error
			description: "World-writable config should generate warning",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			configPath := tt.setupFunc(tmpDir)

			result := &ConfigValidationResult{
				Valid:       true,
				Errors:      []string{},
				Warnings:    []string{},
				Suggestions: []string{},
			}

			err := assessConfigFile(rc, configPath, result)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			t.Logf("Result - Valid: %v, Errors: %d, Warnings: %d",
				result.Valid, len(result.Errors), len(result.Warnings))
		})
	}
}

func TestValidateSemantics(t *testing.T) {
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	tests := []struct {
		name           string
		content        string
		expectErrors   int
		expectWarnings int
		description    string
	}{
		{
			name: "complete_valid_config",
			content: `
storage "file" {
  path = "/opt/vault/data"
}

listener "tcp" {
  address = "0.0.0.0:8179"
  tls_disable = false
}

api_addr = "https://shared.GetInternalHostname:8179"
`,
			expectErrors:   0,
			expectWarnings: 0,
			description:    "Complete config should have no errors",
		},
		{
			name: "missing_required_blocks",
			content: `
api_addr = "https://shared.GetInternalHostname:8179"
`,
			expectErrors:   2, // Missing storage and listener
			expectWarnings: 0,
			description:    "Missing required blocks should generate errors",
		},
		{
			name: "consul_storage_without_address",
			content: `
storage "consul" {
  path = "vault/"
}

listener "tcp" {
  address = "0.0.0.0:8179"
}

api_addr = "https://shared.GetInternalHostname:8179"
`,
			expectErrors:   0,
			expectWarnings: 1, // Warning about missing address
			description:    "Consul storage without address should warn",
		},
		{
			name: "raft_storage_incomplete",
			content: `
storage "raft" {
  path = "/opt/vault/data"
}

listener "tcp" {
  address = "0.0.0.0:8179"
}

api_addr = "https://shared.GetInternalHostname:8179"
`,
			expectErrors:   1, // Missing node_id
			expectWarnings: 0,
			description:    "Raft storage without node_id should error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &ConfigValidationResult{
				Valid:       true,
				Errors:      []string{},
				Warnings:    []string{},
				Suggestions: []string{},
			}

			// Use the new structured validation via validateParsedConfig
			validateParsedConfig(rc, tt.content, result)

			if len(result.Errors) != tt.expectErrors {
				t.Errorf("Expected %d errors, got %d: %v",
					tt.expectErrors, len(result.Errors), result.Errors)
			}

			if len(result.Warnings) < tt.expectWarnings {
				t.Errorf("Expected at least %d warnings, got %d: %v",
					tt.expectWarnings, len(result.Warnings), result.Warnings)
			}

			t.Logf("Errors: %v", result.Errors)
			t.Logf("Warnings: %v", result.Warnings)
		})
	}
}

func TestCheckCommonMisconfigurations(t *testing.T) {
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	tests := []struct {
		name           string
		content        string
		expectWarnings []string
		description    string
	}{
		{
			name: "legacy_port_8200",
			content: `
listener "tcp" {
  address = "0.0.0.0:8200"
}
`,
			expectWarnings: []string{"legacy port 8200"},
			description:    "Should detect legacy port 8200",
		},
		{
			name: "tls_disable_as_string",
			content: `
listener "tcp" {
  tls_disable = "true"
}
`,
			expectWarnings: []string{"tls_disable should be boolean"},
			description:    "Should detect tls_disable as string",
		},
		{
			name: "tls_disabled_warning",
			content: `
listener "tcp" {
  tls_disable = true
}
`,
			expectWarnings: []string{"TLS is disabled"},
			description:    "Should warn about disabled TLS",
		},
		{
			name: "ui_enabled",
			content: `
ui = true
`,
			expectWarnings: []string{}, // Suggestions, not warnings
			description:    "UI enabled should generate suggestion",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &ConfigValidationResult{
				Valid:       true,
				Errors:      []string{},
				Warnings:    []string{},
				Suggestions: []string{},
			}

			// Use the new top-level config validation
			validateTopLevelConfig(rc, tt.content, result)

			// Check if expected warnings are present
			for _, expectedWarning := range tt.expectWarnings {
				found := false
				for _, warning := range result.Warnings {
					if containsSubstring(warning, expectedWarning) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected warning containing '%s' not found in: %v",
						expectedWarning, result.Warnings)
				}
			}

			t.Logf("Warnings: %v", result.Warnings)
			t.Logf("Suggestions: %v", result.Suggestions)
		})
	}
}

// Helper function to check if a string contains a substring (case-insensitive)
func containsSubstring(s, substr string) bool {
	return len(s) >= len(substr) &&
		(s == substr || len(s) > len(substr) &&
			(s[:len(substr)] == substr || s[len(s)-len(substr):] == substr ||
				findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestExtractConfigValue(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		key      string
		expected string
	}{
		{
			name:     "simple_value",
			content:  `path = "/opt/vault/data"`,
			key:      "path",
			expected: "/opt/vault/data",
		},
		{
			name:     "value_with_spaces",
			content:  `tls_cert_file = "/opt/vault/tls/vault.crt"`,
			key:      "tls_cert_file",
			expected: "/opt/vault/tls/vault.crt",
		},
		{
			name:     "value_no_spaces",
			content:  `address="0.0.0.0:8179"`,
			key:      "address",
			expected: "0.0.0.0:8179",
		},
		{
			name:     "key_not_found",
			content:  `other_key = "value"`,
			key:      "missing_key",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractConfigValue(tt.content, tt.key)
			if result != tt.expected {
				t.Errorf("Expected '%s', got '%s'", tt.expected, result)
			}
		})
	}
}
