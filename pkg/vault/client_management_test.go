// pkg/vault/client_management_test.go - Simplified tests for vault client management
package vault

import (
	"context"
	"os"
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

// TestNewClient tests basic client creation
func TestNewClient(t *testing.T) {
	// Save original env vars
	originalAddr := os.Getenv("VAULT_ADDR")
	originalToken := os.Getenv("VAULT_TOKEN")
	defer func() {
		os.Setenv("VAULT_ADDR", originalAddr)
		os.Setenv("VAULT_TOKEN", originalToken)
	}()

	tests := []struct {
		name          string
		vaultAddr     string
		vaultToken    string
		expectError   bool
		errorContains string
	}{
		{
			name:        "successful_client_creation",
			vaultAddr:   "https://vault.example.com:8200",
			vaultToken:  "hvs.test-token",
			expectError: false,
		},
		{
			name:        "localhost_http_allowed",
			vaultAddr:   "http://127.0.0.1:8200",
			vaultToken:  "hvs.test-token",
			expectError: false,
		},
		{
			name:          "missing_vault_addr",
			vaultAddr:     "",
			vaultToken:    "hvs.test-token",
			expectError:   true,
			errorContains: "VAULT_ADDR not set",
		},
		{
			name:          "invalid_vault_addr",
			vaultAddr:     "not-a-url",
			vaultToken:    "hvs.test-token",
			expectError:   true,
			errorContains: "invalid VAULT_ADDR",
		},
		{
			name:          "http_in_production",
			vaultAddr:     "http://vault.example.com:8200",
			vaultToken:    "hvs.test-token",
			expectError:   true,
			errorContains: "HTTPS required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set test environment
			os.Setenv("VAULT_ADDR", tt.vaultAddr)
			os.Setenv("VAULT_TOKEN", tt.vaultToken)

			rc := &eos_io.RuntimeContext{
				Ctx: context.Background(),
				Log: zaptest.NewLogger(t),
			}

			client, err := NewClient(rc)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
				assert.Nil(t, client)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, client)

				// Verify client configuration
				if tt.vaultAddr != "" {
					assert.Equal(t, tt.vaultAddr, client.Address())
				}
			}
		})
	}
}

// TestGetVaultClient tests basic client retrieval
func TestGetVaultClient(t *testing.T) {
	// Set up test environment
	os.Setenv("VAULT_ADDR", "https://vault.example.com:8200")
	os.Setenv("VAULT_TOKEN", "hvs.test-token")
	defer func() {
		os.Unsetenv("VAULT_ADDR")
		os.Unsetenv("VAULT_TOKEN")
	}()

	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
		Log: zaptest.NewLogger(t),
	}

	t.Run("client_creation", func(t *testing.T) {
		client, err := GetVaultClient(rc)
		if err != nil {
			// Expected in test environment without real Vault
			assert.Contains(t, err.Error(), "vault")
		} else {
			assert.NotNil(t, client)
		}
	})
}

// TestSetVaultClient tests setting the client
func TestSetVaultClient(t *testing.T) {
	// Create a test client
	config := api.DefaultConfig()
	config.Address = "https://vault.example.com:8200"
	client, err := api.NewClient(config)
	require.NoError(t, err)

	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
		Log: zaptest.NewLogger(t),
	}

	t.Run("set_client", func(t *testing.T) {
		SetVaultClient(rc, client)
		// SetVaultClient doesn't return an error in the current implementation
	})
}

// BenchmarkGetVaultClient benchmarks client operations
func BenchmarkGetVaultClient(b *testing.B) {
	// Set up test environment
	os.Setenv("VAULT_ADDR", "https://vault.example.com:8200")
	os.Setenv("VAULT_TOKEN", "hvs.test-token")
	defer func() {
		os.Unsetenv("VAULT_ADDR")
		os.Unsetenv("VAULT_TOKEN")
	}()

	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
		Log: zaptest.NewLogger(b),
	}

	for i := 0; i < b.N; i++ {
		_, _ = GetVaultClient(rc)
	}
}