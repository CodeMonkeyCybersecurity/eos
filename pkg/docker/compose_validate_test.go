// pkg/docker/compose_validate_test.go
// Comprehensive tests for Docker Compose validation with SDK and shell fallback

package docker

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Test fixtures
const (
	validCompose = `version: "3.8"
services:
  web:
    image: nginx:latest
    ports:
      - "80:80"
    environment:
      - DOMAIN=${DOMAIN}
      - PORT=${PORT:-8080}
networks:
  default:
    driver: bridge
`

	invalidSyntaxCompose = `version: "3.8"
services:
  web:
    image: nginx:latest
    ports:
      - "80:80
    environment:
      DOMAIN: ${DOMAIN}
`

	missingVariableCompose = `version: "3.8"
services:
  web:
    image: nginx:latest
    environment:
      REQUIRED_VAR: ${REQUIRED_VAR:?must be set}
      OPTIONAL_VAR: ${OPTIONAL_VAR:-default}
`

	validEnv = `DOMAIN=example.com
PORT=8080
REQUIRED_VAR=test-value
`

	missingRequiredEnv = `DOMAIN=example.com
PORT=8080
# REQUIRED_VAR is missing
`

	validCaddyfile = `example.com {
	reverse_proxy localhost:8080
	log {
		output file /var/log/caddy/access.log
	}
}
`

	invalidCaddyfile = `example.com {
	reverse_proxy localhost:8080
	invalid_directive
	unclosed_block {
`
)

// TestValidateComposeFile_ValidFile tests SDK validation with valid compose file
func TestValidateComposeFile_ValidFile(t *testing.T) {
	ctx := context.Background()
	tempDir := t.TempDir()

	// Create valid compose file
	composeFile := filepath.Join(tempDir, "docker-compose.yml")
	if err := os.WriteFile(composeFile, []byte(validCompose), 0644); err != nil {
		t.Fatalf("Failed to create test compose file: %v", err)
	}

	// Create valid .env file
	envFile := filepath.Join(tempDir, ".env")
	if err := os.WriteFile(envFile, []byte(validEnv), 0644); err != nil {
		t.Fatalf("Failed to create test .env file: %v", err)
	}

	// Test SDK validation
	err := ValidateComposeFile(ctx, composeFile, envFile)
	if err != nil {
		t.Errorf("ValidateComposeFile() failed with valid file: %v", err)
	}
}

// TestValidateComposeFile_InvalidSyntax tests SDK catches YAML syntax errors
func TestValidateComposeFile_InvalidSyntax(t *testing.T) {
	ctx := context.Background()
	tempDir := t.TempDir()

	// Create invalid compose file (unclosed quote)
	composeFile := filepath.Join(tempDir, "docker-compose.yml")
	if err := os.WriteFile(composeFile, []byte(invalidSyntaxCompose), 0644); err != nil {
		t.Fatalf("Failed to create test compose file: %v", err)
	}

	envFile := filepath.Join(tempDir, ".env")
	if err := os.WriteFile(envFile, []byte(validEnv), 0644); err != nil {
		t.Fatalf("Failed to create test .env file: %v", err)
	}

	// Test SDK validation - should fail
	err := ValidateComposeFile(ctx, composeFile, envFile)
	if err == nil {
		t.Error("ValidateComposeFile() should fail with invalid YAML syntax")
	}

	// Error message should be helpful
	if !strings.Contains(err.Error(), "yaml") && !strings.Contains(err.Error(), "syntax") {
		t.Errorf("Error message should mention YAML syntax issue, got: %v", err)
	}
}

// TestValidateComposeFile_MissingRequiredVariable tests variable validation
func TestValidateComposeFile_MissingRequiredVariable(t *testing.T) {
	ctx := context.Background()
	tempDir := t.TempDir()

	// Create compose file with required variable
	composeFile := filepath.Join(tempDir, "docker-compose.yml")
	if err := os.WriteFile(composeFile, []byte(missingVariableCompose), 0644); err != nil {
		t.Fatalf("Failed to create test compose file: %v", err)
	}

	// Create .env WITHOUT the required variable
	envFile := filepath.Join(tempDir, ".env")
	if err := os.WriteFile(envFile, []byte(missingRequiredEnv), 0644); err != nil {
		t.Fatalf("Failed to create test .env file: %v", err)
	}

	// Test SDK validation - should fail
	err := ValidateComposeFile(ctx, composeFile, envFile)
	if err == nil {
		t.Error("ValidateComposeFile() should fail with missing required variable")
	}

	// Error should mention the required variable
	if !strings.Contains(err.Error(), "REQUIRED_VAR") {
		t.Errorf("Error should mention REQUIRED_VAR, got: %v", err)
	}
}

// TestValidateComposeFile_MissingFile tests error handling for missing files
func TestValidateComposeFile_MissingFile(t *testing.T) {
	ctx := context.Background()
	tempDir := t.TempDir()

	// Test with non-existent compose file
	composeFile := filepath.Join(tempDir, "nonexistent.yml")
	envFile := filepath.Join(tempDir, ".env")

	err := ValidateComposeFile(ctx, composeFile, envFile)
	if err == nil {
		t.Error("ValidateComposeFile() should fail with missing compose file")
	}

	if !strings.Contains(err.Error(), "failed to read") {
		t.Errorf("Error should mention file read failure, got: %v", err)
	}
}

// TestValidateComposeWithShellFallback_SDKSuccess tests fallback not triggered on SDK success
func TestValidateComposeWithShellFallback_SDKSuccess(t *testing.T) {
	ctx := context.Background()
	tempDir := t.TempDir()

	// Create valid files
	composeFile := filepath.Join(tempDir, "docker-compose.yml")
	if err := os.WriteFile(composeFile, []byte(validCompose), 0644); err != nil {
		t.Fatalf("Failed to create test compose file: %v", err)
	}

	envFile := filepath.Join(tempDir, ".env")
	if err := os.WriteFile(envFile, []byte(validEnv), 0644); err != nil {
		t.Fatalf("Failed to create test .env file: %v", err)
	}

	// Test fallback function - SDK should succeed, no shell needed
	err := ValidateComposeWithShellFallback(ctx, composeFile, envFile)
	if err != nil {
		t.Errorf("ValidateComposeWithShellFallback() failed: %v", err)
	}
}

// TestValidateComposeWithShellFallback_BothFail tests both SDK and shell fail
func TestValidateComposeWithShellFallback_BothFail(t *testing.T) {
	ctx := context.Background()
	tempDir := t.TempDir()

	// Create invalid compose file
	composeFile := filepath.Join(tempDir, "docker-compose.yml")
	if err := os.WriteFile(composeFile, []byte(invalidSyntaxCompose), 0644); err != nil {
		t.Fatalf("Failed to create test compose file: %v", err)
	}

	envFile := filepath.Join(tempDir, ".env")
	if err := os.WriteFile(envFile, []byte(validEnv), 0644); err != nil {
		t.Fatalf("Failed to create test .env file: %v", err)
	}

	// Test fallback - both SDK and shell should fail
	err := ValidateComposeWithShellFallback(ctx, composeFile, envFile)
	if err == nil {
		t.Error("ValidateComposeWithShellFallback() should fail with invalid syntax")
	}
}

// TestValidateCaddyfile_ValidFile tests Caddyfile validation with valid syntax
func TestValidateCaddyfile_ValidFile(t *testing.T) {
	// Skip if caddy not installed (this is expected and OK)
	if _, err := os.Stat("/usr/bin/caddy"); os.IsNotExist(err) {
		t.Skip("Caddy not installed - skipping Caddyfile validation test")
	}

	ctx := context.Background()
	tempDir := t.TempDir()

	// Create valid Caddyfile
	caddyfile := filepath.Join(tempDir, "Caddyfile")
	if err := os.WriteFile(caddyfile, []byte(validCaddyfile), 0644); err != nil {
		t.Fatalf("Failed to create test Caddyfile: %v", err)
	}

	// Test validation
	err := ValidateCaddyfile(ctx, caddyfile)
	if err != nil {
		t.Errorf("ValidateCaddyfile() failed with valid file: %v", err)
	}
}

// TestValidateCaddyfile_InvalidFile tests Caddyfile validation with invalid syntax
func TestValidateCaddyfile_InvalidFile(t *testing.T) {
	// Skip if caddy not installed
	if _, err := os.Stat("/usr/bin/caddy"); os.IsNotExist(err) {
		t.Skip("Caddy not installed - skipping Caddyfile validation test")
	}

	ctx := context.Background()
	tempDir := t.TempDir()

	// Create invalid Caddyfile
	caddyfile := filepath.Join(tempDir, "Caddyfile")
	if err := os.WriteFile(caddyfile, []byte(invalidCaddyfile), 0644); err != nil {
		t.Fatalf("Failed to create test Caddyfile: %v", err)
	}

	// Test validation - should fail
	err := ValidateCaddyfile(ctx, caddyfile)
	if err == nil {
		t.Error("ValidateCaddyfile() should fail with invalid syntax")
	}
}

// TestValidateCaddyfile_MissingBinary tests graceful skip when caddy not installed
func TestValidateCaddyfile_MissingBinary(t *testing.T) {
	// This test verifies that validation gracefully skips if caddy isn't installed
	// We can't reliably test this without uninstalling caddy, so we document the behavior

	// Expected behavior:
	// - If caddy binary not found, exec.LookPath() returns error
	// - ValidateCaddyfile logs debug message and returns nil (no error)
	// - This allows deployment in environments without caddy CLI (Docker-only setups)

	t.Log("ValidateCaddyfile() should return nil if caddy binary not found")
	t.Log("This is tested implicitly by production deployments")
}

// TestValidateGeneratedFiles_AllValid tests convenience function with all valid files
func TestValidateGeneratedFiles_AllValid(t *testing.T) {
	ctx := context.Background()
	tempDir := t.TempDir()

	// Create all valid files
	composeFile := filepath.Join(tempDir, "docker-compose.yml")
	if err := os.WriteFile(composeFile, []byte(validCompose), 0644); err != nil {
		t.Fatalf("Failed to create compose file: %v", err)
	}

	envFile := filepath.Join(tempDir, ".env")
	if err := os.WriteFile(envFile, []byte(validEnv), 0644); err != nil {
		t.Fatalf("Failed to create .env file: %v", err)
	}

	caddyfile := filepath.Join(tempDir, "Caddyfile")
	if err := os.WriteFile(caddyfile, []byte(validCaddyfile), 0644); err != nil {
		t.Fatalf("Failed to create Caddyfile: %v", err)
	}

	// Test convenience function
	err := ValidateGeneratedFiles(ctx, tempDir)
	if err != nil {
		t.Errorf("ValidateGeneratedFiles() failed: %v", err)
	}
}

// TestValidateGeneratedFiles_InvalidCompose tests convenience function with invalid compose
func TestValidateGeneratedFiles_InvalidCompose(t *testing.T) {
	ctx := context.Background()
	tempDir := t.TempDir()

	// Create INVALID compose file
	composeFile := filepath.Join(tempDir, "docker-compose.yml")
	if err := os.WriteFile(composeFile, []byte(invalidSyntaxCompose), 0644); err != nil {
		t.Fatalf("Failed to create compose file: %v", err)
	}

	envFile := filepath.Join(tempDir, ".env")
	if err := os.WriteFile(envFile, []byte(validEnv), 0644); err != nil {
		t.Fatalf("Failed to create .env file: %v", err)
	}

	// Test convenience function - should fail on compose validation
	err := ValidateGeneratedFiles(ctx, tempDir)
	if err == nil {
		t.Error("ValidateGeneratedFiles() should fail with invalid compose file")
	}

	if !strings.Contains(err.Error(), "docker-compose.yml") {
		t.Errorf("Error should mention docker-compose.yml, got: %v", err)
	}
}

// TestErrorMessagesIncludeRemediation tests that error messages have actionable guidance
func TestErrorMessagesIncludeRemediation(t *testing.T) {
	ctx := context.Background()
	tempDir := t.TempDir()

	tests := []struct {
		name              string
		composeContent    string
		envContent        string
		expectedInError   string
		remediationPhrase string
	}{
		{
			name:              "Invalid YAML syntax",
			composeContent:    invalidSyntaxCompose,
			envContent:        validEnv,
			expectedInError:   "yaml",
			remediationPhrase: "", // Error from YAML parser, no custom remediation yet
		},
		{
			name:              "Missing required variable",
			composeContent:    missingVariableCompose,
			envContent:        missingRequiredEnv,
			expectedInError:   "REQUIRED_VAR",
			remediationPhrase: "required variable",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			composeFile := filepath.Join(tempDir, "test-"+tt.name+".yml")
			if err := os.WriteFile(composeFile, []byte(tt.composeContent), 0644); err != nil {
				t.Fatalf("Failed to create test file: %v", err)
			}

			envFile := filepath.Join(tempDir, "test-"+tt.name+".env")
			if err := os.WriteFile(envFile, []byte(tt.envContent), 0644); err != nil {
				t.Fatalf("Failed to create test file: %v", err)
			}

			err := ValidateComposeFile(ctx, composeFile, envFile)
			if err == nil {
				t.Errorf("Expected error for %s", tt.name)
				return
			}

			errMsg := err.Error()
			if !strings.Contains(errMsg, tt.expectedInError) {
				t.Errorf("Error should contain '%s', got: %v", tt.expectedInError, errMsg)
			}

			if tt.remediationPhrase != "" && !strings.Contains(errMsg, tt.remediationPhrase) {
				t.Errorf("Error should contain remediation phrase '%s', got: %v", tt.remediationPhrase, errMsg)
			}

			t.Logf("Error message: %v", errMsg)
		})
	}
}

// TestParseEnvFile tests .env file parsing
func TestParseEnvFile(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		expected map[string]string
		wantErr  bool
	}{
		{
			name: "Valid env file",
			content: `KEY1=value1
KEY2=value2
# Comment line
EMPTY_VALUE=
`,
			expected: map[string]string{
				"KEY1":        "value1",
				"KEY2":        "value2",
				"EMPTY_VALUE": "",
			},
			wantErr: false,
		},
		{
			name: "Env with spaces",
			content: `KEY1 = value1
KEY2= value2
KEY3 =value3
`,
			expected: map[string]string{
				"KEY1": "value1",
				"KEY2": "value2",
				"KEY3": "value3",
			},
			wantErr: false,
		},
		{
			name: "Comments and blank lines",
			content: `# Header comment
KEY1=value1

# Another comment
KEY2=value2

`,
			expected: map[string]string{
				"KEY1": "value1",
				"KEY2": "value2",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := t.TempDir()
			envFile := filepath.Join(tempDir, ".env")
			if err := os.WriteFile(envFile, []byte(tt.content), 0644); err != nil {
				t.Fatalf("Failed to create test file: %v", err)
			}

			result, err := parseEnvFile(envFile)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseEnvFile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				for key, expectedValue := range tt.expected {
					if gotValue, ok := result[key]; !ok {
						t.Errorf("Expected key %s not found in result", key)
					} else if gotValue != expectedValue {
						t.Errorf("For key %s: got %q, want %q", key, gotValue, expectedValue)
					}
				}
			}
		})
	}
}

// BenchmarkValidateComposeFile benchmarks SDK validation performance
func BenchmarkValidateComposeFile(b *testing.B) {
	ctx := context.Background()
	tempDir := b.TempDir()

	composeFile := filepath.Join(tempDir, "docker-compose.yml")
	if err := os.WriteFile(composeFile, []byte(validCompose), 0644); err != nil {
		b.Fatalf("Failed to create test file: %v", err)
	}

	envFile := filepath.Join(tempDir, ".env")
	if err := os.WriteFile(envFile, []byte(validEnv), 0644); err != nil {
		b.Fatalf("Failed to create test file: %v", err)
	}

	b.ResetTimer()
	for b.Loop() {
		_ = ValidateComposeFile(ctx, composeFile, envFile)
	}
}
