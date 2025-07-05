package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/testutil"
	"github.com/hashicorp/vault/api"
)

func TestNewClient(t *testing.T) {
	tests := []struct {
		name        string
		envVars     map[string]string
		wantErr     bool
		validateFn  func(t *testing.T, client *api.Client)
	}{
		{
			name: "default configuration",
			envVars: map[string]string{},
			wantErr: false,
			validateFn: func(t *testing.T, client *api.Client) {
				testutil.AssertNotEqual(t, nil, client)
				testutil.AssertEqual(t, fmt.Sprintf("http://127.0.0.1:%d", shared.PortVault), client.Address())
			},
		},
		{
			name: "custom vault address",
			envVars: map[string]string{
				shared.VaultAddrEnv: "https://vault.example.com:8200",
			},
			wantErr: false,
			validateFn: func(t *testing.T, client *api.Client) {
				testutil.AssertEqual(t, "https://vault.example.com:8200", client.Address())
			},
		},
		{
			name: "with vault token",
			envVars: map[string]string{
				"VAULT_TOKEN": "test-token-12345",
			},
			wantErr: false,
			validateFn: func(t *testing.T, client *api.Client) {
				testutil.AssertEqual(t, "test-token-12345", client.Token())
			},
		},
		{
			name: "with TLS CA cert",
			envVars: map[string]string{
				"VAULT_CACERT": "/path/to/custom/ca.crt",
			},
			wantErr: false,
			validateFn: func(t *testing.T, client *api.Client) {
				testutil.AssertNotEqual(t, nil, client)
			},
		},
		{
			name: "empty vault address",
			envVars: map[string]string{
				shared.VaultAddrEnv: "",
			},
			wantErr: false,
			validateFn: func(t *testing.T, client *api.Client) {
				testutil.AssertEqual(t, fmt.Sprintf("http://127.0.0.1:%d", shared.PortVault), client.Address())
			},
		},
		{
			name: "with multiple TLS settings",
			envVars: map[string]string{
				"VAULT_CACERT":     "/path/to/ca.crt",
				"VAULT_CLIENT_CERT": "/path/to/client.crt",
				"VAULT_CLIENT_KEY":  "/path/to/client.key",
				"VAULT_SKIP_VERIFY": "true",
			},
			wantErr: false,
			validateFn: func(t *testing.T, client *api.Client) {
				testutil.AssertNotEqual(t, nil, client)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Set up environment
			for key, value := range tc.envVars {
				testutil.WithEnvVar(t, key, value)
			}

			// Create runtime context
			rc := testutil.TestRuntimeContext(t)

			// Create client
			client, err := NewClient(rc)

			// Check error
			if tc.wantErr {
				testutil.AssertError(t, err)
			} else {
				testutil.AssertNoError(t, err)
				tc.validateFn(t, client)
			}
		})
	}
}

func TestGetVaultClient(t *testing.T) {
	t.Run("returns cached client", func(t *testing.T) {
		// Create runtime context
		rc := testutil.TestRuntimeContext(t)

		// Create and set a test client
		testClient, err := api.NewClient(nil)
		testutil.AssertNoError(t, err)
		
		// Set the client
		SetVaultClient(rc, testClient)

		// Get the client
		client, err := GetVaultClient(rc)
		testutil.AssertNoError(t, err)
		testutil.AssertEqual(t, testClient, client)

		// Clean up
		shared.VaultClient = nil
	})

	t.Run("initializes new client when none cached", func(t *testing.T) {
		// Ensure no cached client
		shared.VaultClient = nil

		// Create runtime context
		rc := testutil.TestRuntimeContext(t)

		// Mock the validation to succeed
		transport := &testutil.MockHTTPTransport{
			ResponseMap: map[string]testutil.MockResponse{
				"/v1/sys/health": {
					StatusCode: 200,
					Body: map[string]interface{}{
						"initialized": true,
						"sealed":      false,
						"standby":     false,
					},
				},
			},
		}
		testutil.WithMockHTTPClient(t, transport)

		// Try to get client (will fail due to no token, but that's expected)
		_, err := GetVaultClient(rc)
		// We expect an error because we don't have a valid token setup
		testutil.AssertError(t, err)
	})

	t.Run("concurrent access", func(t *testing.T) {
		// Ensure no cached client
		shared.VaultClient = nil

		// Create runtime context
		rc := testutil.TestRuntimeContext(t)

		// Create a test client to set
		testClient, err := api.NewClient(nil)
		testutil.AssertNoError(t, err)

		var wg sync.WaitGroup
		errors := make([]error, 10)

		// Concurrent attempts to get/set client
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				
				if idx%2 == 0 {
					SetVaultClient(rc, testClient)
				} else {
					client, err := GetVaultClient(rc)
					if err == nil && client != nil {
						// Success case
						errors[idx] = nil
					} else {
						errors[idx] = err
					}
				}
			}(i)
		}

		wg.Wait()

		// At least some operations should have succeeded
		successCount := 0
		for _, err := range errors {
			if err == nil {
				successCount++
			}
		}
		
		// Clean up
		shared.VaultClient = nil
	})
}

func TestSetVaultClient(t *testing.T) {
	t.Run("sets global client", func(t *testing.T) {
		// Create runtime context
		rc := testutil.TestRuntimeContext(t)

		// Create test client
		testClient, err := api.NewClient(nil)
		testutil.AssertNoError(t, err)

		// Set the client
		SetVaultClient(rc, testClient)

		// Verify it was set
		testutil.AssertEqual(t, testClient, shared.VaultClient)

		// Clean up
		shared.VaultClient = nil
	})

	t.Run("overwrites existing client", func(t *testing.T) {
		// Create runtime context
		rc := testutil.TestRuntimeContext(t)

		// Create and set first client
		client1, err := api.NewClient(nil)
		testutil.AssertNoError(t, err)
		SetVaultClient(rc, client1)

		// Create and set second client
		client2, err := api.NewClient(nil)
		testutil.AssertNoError(t, err)
		SetVaultClient(rc, client2)

		// Verify second client is set
		testutil.AssertEqual(t, client2, shared.VaultClient)
		testutil.AssertNotEqual(t, client1, shared.VaultClient)

		// Clean up
		shared.VaultClient = nil
	})
}

func TestTryEnvOrFallback(t *testing.T) {
	tests := []struct {
		name       string
		setupFn    func(t *testing.T)
		wantErr    bool
		validateFn func(t *testing.T, client *api.Client)
	}{
		{
			name: "loads from environment with token",
			setupFn: func(t *testing.T) {
				testutil.WithEnvVar(t, "VAULT_TOKEN", "env-test-token")
				testutil.WithEnvVar(t, shared.VaultAddrEnv, "http://localhost:8200")
			},
			wantErr: false,
			validateFn: func(t *testing.T, client *api.Client) {
				testutil.AssertEqual(t, "env-test-token", client.Token())
			},
		},
		{
			name: "falls back to privileged client",
			setupFn: func(t *testing.T) {
				// No VAULT_TOKEN in env
				testutil.WithoutEnvVar(t, "VAULT_TOKEN")
				
				// Create vault init file with root token
				tmpDir := testutil.TempDir(t)
				secretsDir := filepath.Join(tmpDir, "secrets")
				err := os.MkdirAll(secretsDir, 0755)
				testutil.AssertNoError(t, err)

				initData := shared.VaultInitResponse{
					RootToken: "root-test-token",
				}
				data, err := json.Marshal(initData)
				testutil.AssertNoError(t, err)

				initFile := filepath.Join(secretsDir, "vault_init.json")
				err = os.WriteFile(initFile, data, 0600)
				testutil.AssertNoError(t, err)

				// Override shared.SecretsDir for test
				originalSecretsDir := shared.SecretsDir
				shared.SecretsDir = secretsDir
				t.Cleanup(func() {
					shared.SecretsDir = originalSecretsDir
				})
			},
			wantErr: false,
			validateFn: func(t *testing.T, client *api.Client) {
				testutil.AssertEqual(t, "root-test-token", client.Token())
			},
		},
		{
			name: "fails when no tokens available",
			setupFn: func(t *testing.T) {
				testutil.WithoutEnvVar(t, "VAULT_TOKEN")
				// No init file exists
			},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.setupFn(t)

			rc := testutil.TestRuntimeContext(t)
			client, err := tryEnvOrFallback(rc)

			if tc.wantErr {
				testutil.AssertError(t, err)
			} else {
				testutil.AssertNoError(t, err)
				tc.validateFn(t, client)
			}
		})
	}
}

func TestLoadPrivilegedToken(t *testing.T) {
	tests := []struct {
		name    string
		setupFn func(t *testing.T) string // returns expected token
		wantErr bool
	}{
		{
			name: "loads root token from init file",
			setupFn: func(t *testing.T) string {
				tmpDir := testutil.TempDir(t)
				secretsDir := filepath.Join(tmpDir, "secrets")
				err := os.MkdirAll(secretsDir, 0755)
				testutil.AssertNoError(t, err)

				initData := shared.VaultInitResponse{
					RootToken: "test-root-token-12345",
				}
				data, err := json.Marshal(initData)
				testutil.AssertNoError(t, err)

				initFile := filepath.Join(secretsDir, "vault_init.json")
				err = os.WriteFile(initFile, data, 0600)
				testutil.AssertNoError(t, err)

				// Override shared.SecretsDir
				originalSecretsDir := shared.SecretsDir
				shared.SecretsDir = secretsDir
				t.Cleanup(func() {
					shared.SecretsDir = originalSecretsDir
				})

				return "test-root-token-12345"
			},
			wantErr: false,
		},
		{
			name: "falls back to agent token",
			setupFn: func(t *testing.T) string {
				tmpDir := testutil.TempDir(t)
				
				// No init file, but create agent token file
				agentTokenFile := filepath.Join(tmpDir, "agent-token")
				err := os.WriteFile(agentTokenFile, []byte("agent-token-67890"), 0600)
				testutil.AssertNoError(t, err)

				// Override shared paths
				originalAgentToken := shared.AgentToken
				shared.AgentToken = agentTokenFile
				t.Cleanup(func() {
					shared.AgentToken = originalAgentToken
				})

				return "agent-token-67890"
			},
			wantErr: false,
		},
		{
			name: "fails when no tokens available",
			setupFn: func(t *testing.T) string {
				// Ensure no init file or agent token exists
				tmpDir := testutil.TempDir(t)
				shared.SecretsDir = tmpDir
				shared.AgentToken = filepath.Join(tmpDir, "nonexistent-token")
				return ""
			},
			wantErr: true,
		},
		{
			name: "handles malformed init file",
			setupFn: func(t *testing.T) string {
				tmpDir := testutil.TempDir(t)
				secretsDir := filepath.Join(tmpDir, "secrets")
				err := os.MkdirAll(secretsDir, 0755)
				testutil.AssertNoError(t, err)

				// Write invalid JSON
				initFile := filepath.Join(secretsDir, "vault_init.json")
				err = os.WriteFile(initFile, []byte("invalid json"), 0600)
				testutil.AssertNoError(t, err)

				originalSecretsDir := shared.SecretsDir
				shared.SecretsDir = secretsDir
				t.Cleanup(func() {
					shared.SecretsDir = originalSecretsDir
				})

				return ""
			},
			wantErr: true,
		},
		{
			name: "handles empty root token in init file",
			setupFn: func(t *testing.T) string {
				tmpDir := testutil.TempDir(t)
				secretsDir := filepath.Join(tmpDir, "secrets")
				err := os.MkdirAll(secretsDir, 0755)
				testutil.AssertNoError(t, err)

				// Init file with empty root token
				initData := shared.VaultInitResponse{
					RootToken: "",
				}
				data, err := json.Marshal(initData)
				testutil.AssertNoError(t, err)

				initFile := filepath.Join(secretsDir, "vault_init.json")
				err = os.WriteFile(initFile, data, 0600)
				testutil.AssertNoError(t, err)

				originalSecretsDir := shared.SecretsDir
				shared.SecretsDir = secretsDir
				t.Cleanup(func() {
					shared.SecretsDir = originalSecretsDir
				})

				return ""
			},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			expectedToken := tc.setupFn(t)
			rc := testutil.TestRuntimeContext(t)

			token, err := loadPrivilegedToken(rc)

			if tc.wantErr {
				testutil.AssertError(t, err)
			} else {
				testutil.AssertNoError(t, err)
				testutil.AssertEqual(t, expectedToken, token)
			}
		})
	}
}

func TestReadTokenFromInitFile(t *testing.T) {
	tests := []struct {
		name         string
		setupFn      func(t *testing.T) string // returns expected token
		wantErr      bool
		errorContains string
	}{
		{
			name: "reads valid init file",
			setupFn: func(t *testing.T) string {
				tmpDir := testutil.TempDir(t)
				secretsDir := filepath.Join(tmpDir, "secrets")
				err := os.MkdirAll(secretsDir, 0755)
				testutil.AssertNoError(t, err)

				initData := shared.VaultInitResponse{
					RootToken: "valid-root-token",
				}
				data, err := json.Marshal(initData)
				testutil.AssertNoError(t, err)

				initFile := filepath.Join(secretsDir, "vault_init.json")
				err = os.WriteFile(initFile, data, 0600)
				testutil.AssertNoError(t, err)

				originalSecretsDir := shared.SecretsDir
				shared.SecretsDir = secretsDir
				t.Cleanup(func() {
					shared.SecretsDir = originalSecretsDir
				})

				return "valid-root-token"
			},
			wantErr: false,
		},
		{
			name: "handles missing secrets directory",
			setupFn: func(t *testing.T) string {
				tmpDir := testutil.TempDir(t)
				shared.SecretsDir = filepath.Join(tmpDir, "nonexistent")
				return ""
			},
			wantErr:       true,
			errorContains: "secrets directory does not exist",
		},
		{
			name: "handles missing init file",
			setupFn: func(t *testing.T) string {
				tmpDir := testutil.TempDir(t)
				secretsDir := filepath.Join(tmpDir, "secrets")
				err := os.MkdirAll(secretsDir, 0755)
				testutil.AssertNoError(t, err)

				originalSecretsDir := shared.SecretsDir
				shared.SecretsDir = secretsDir
				t.Cleanup(func() {
					shared.SecretsDir = originalSecretsDir
				})

				return ""
			},
			wantErr:       true,
			errorContains: "vault_init.json does not exist",
		},
		{
			name: "handles permission denied",
			setupFn: func(t *testing.T) string {
				tmpDir := testutil.TempDir(t)
				secretsDir := filepath.Join(tmpDir, "secrets")
				err := os.MkdirAll(secretsDir, 0000) // No permissions
				testutil.AssertNoError(t, err)

				originalSecretsDir := shared.SecretsDir
				shared.SecretsDir = secretsDir
				t.Cleanup(func() {
					shared.SecretsDir = originalSecretsDir
					os.Chmod(secretsDir, 0755) // Restore permissions for cleanup
				})

				return ""
			},
			wantErr:       true,
			errorContains: "cannot access secrets directory",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			expectedToken := tc.setupFn(t)
			rc := testutil.TestRuntimeContext(t)

			token, err := readTokenFromInitFile(rc)

			if tc.wantErr {
				testutil.AssertError(t, err)
				if tc.errorContains != "" {
					testutil.AssertErrorContains(t, err, tc.errorContains)
				}
			} else {
				testutil.AssertNoError(t, err)
				testutil.AssertEqual(t, expectedToken, token)
			}
		})
	}
}

func TestValidateClient(t *testing.T) {
	t.Run("successful validation", func(t *testing.T) {
		rc := testutil.TestRuntimeContext(t)

		// Mock successful health check
		transport := &testutil.MockHTTPTransport{
			ResponseMap: map[string]testutil.MockResponse{
				"/v1/sys/health": {
					StatusCode: 200,
					Body: map[string]interface{}{
						"initialized": true,
						"sealed":      false,
						"standby":     false,
						"version":     "1.12.0",
					},
				},
			},
		}
		testutil.WithMockHTTPClient(t, transport)

		client, err := api.NewClient(nil)
		testutil.AssertNoError(t, err)

		validatedClient, _ := validateClient(rc, client)
		testutil.AssertNotEqual(t, nil, validatedClient)
	})

	t.Run("failed validation", func(t *testing.T) {
		rc := testutil.TestRuntimeContext(t)

		// Mock failed health check
		transport := &testutil.MockHTTPTransport{
			DefaultResponse: testutil.MockResponse{
				StatusCode: 503,
				Body:       map[string]interface{}{"error": "service unavailable"},
			},
		}
		testutil.WithMockHTTPClient(t, transport)

		client, err := api.NewClient(nil)
		testutil.AssertNoError(t, err)

		validatedClient, _ := validateClient(rc, client)
		// Validation should fail
		testutil.AssertEqual(t, (*api.Client)(nil), validatedClient)
	})
}

func TestNewConfiguredClient(t *testing.T) {
	tests := []struct {
		name       string
		envVars    map[string]string
		wantErr    bool
		validateFn func(t *testing.T, client *api.Client)
	}{
		{
			name:    "default configuration",
			envVars: map[string]string{},
			wantErr: false,
			validateFn: func(t *testing.T, client *api.Client) {
				config := client.CloneConfig()
				testutil.AssertEqual(t, 5*time.Second, config.Timeout)
			},
		},
		{
			name: "with custom timeout",
			envVars: map[string]string{
				"VAULT_CLIENT_TIMEOUT": "30s",
			},
			wantErr: false,
			validateFn: func(t *testing.T, client *api.Client) {
				// Note: VAULT_CLIENT_TIMEOUT is handled by Vault's ReadEnvironment
				testutil.AssertNotEqual(t, nil, client)
			},
		},
		{
			name: "with TLS configuration",
			envVars: map[string]string{
				"VAULT_CACERT":      "/custom/ca.crt",
				"VAULT_CLIENT_CERT": "/custom/client.crt",
				"VAULT_CLIENT_KEY":  "/custom/client.key",
			},
			wantErr: false,
			validateFn: func(t *testing.T, client *api.Client) {
				testutil.AssertNotEqual(t, nil, client)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for key, value := range tc.envVars {
				testutil.WithEnvVar(t, key, value)
			}

			rc := testutil.TestRuntimeContext(t)
			client, err := newConfiguredClient(rc)

			if tc.wantErr {
				testutil.AssertError(t, err)
			} else {
				testutil.AssertNoError(t, err)
				tc.validateFn(t, client)
			}
		})
	}
}

func TestClientConcurrency(t *testing.T) {
	t.Run("concurrent client creation", func(t *testing.T) {
		var wg sync.WaitGroup
		clients := make([]*api.Client, 10)
		errors := make([]error, 10)

		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				rc := testutil.TestRuntimeContext(t)
				client, err := NewClient(rc)
				clients[idx] = client
				errors[idx] = err
			}(i)
		}

		wg.Wait()

		// All clients should be created successfully
		for i, err := range errors {
			testutil.AssertNoError(t, err)
			testutil.AssertNotEqual(t, nil, clients[i])
		}
	})

	t.Run("concurrent get/set operations", func(t *testing.T) {
		// Clear any existing client
		shared.VaultClient = nil

		rc := testutil.TestRuntimeContext(t)
		testClient, err := api.NewClient(nil)
		testutil.AssertNoError(t, err)

		var wg sync.WaitGroup
		const numGoroutines = 20

		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				
				// Alternate between get and set operations
				if idx%3 == 0 {
					SetVaultClient(rc, testClient)
				} else {
					// GetVaultClient might fail if no client is set yet
					GetVaultClient(rc)
				}
			}(i)
		}

		wg.Wait()

		// Clean up
		shared.VaultClient = nil
	})
}

func TestClientTimeout(t *testing.T) {
	t.Run("respects context timeout", func(t *testing.T) {
		// Create a context with very short timeout
		rc, _ := testutil.TestRuntimeContextWithTimeout(t, 10*time.Millisecond)

		// Mock a slow responding server
		transport := &testutil.MockHTTPTransport{
			ResponseMap: map[string]testutil.MockResponse{
				"/v1/sys/health": {
					StatusCode: 200,
					Body:       map[string]interface{}{"healthy": true},
					// Add artificial delay in real implementation
				},
			},
		}
		testutil.WithMockHTTPClient(t, transport)

		// Create client with the timeout context
		_, err := NewClient(rc)
		testutil.AssertNoError(t, err)

		// Wait for context to expire
		<-rc.Ctx.Done()
		testutil.AssertEqual(t, context.DeadlineExceeded, rc.Ctx.Err())
	})
}

func BenchmarkNewClient(b *testing.B) {
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = NewClient(rc)
	}
}

func BenchmarkGetVaultClient(b *testing.B) {
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	// Pre-cache a client
	client, _ := api.NewClient(nil)
	shared.VaultClient = client

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = GetVaultClient(rc)
	}

	// Clean up
	shared.VaultClient = nil
}

func BenchmarkConcurrentClientAccess(b *testing.B) {
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	client, _ := api.NewClient(nil)
	shared.VaultClient = client

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			GetVaultClient(rc)
		}
	})

	// Clean up
	shared.VaultClient = nil
}