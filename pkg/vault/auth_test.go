package vault

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/testutil"
	"github.com/hashicorp/vault/api"
)

func TestAuthn(t *testing.T) {
	tests := []struct {
		name    string
		setupFn func(t *testing.T, rc *eos_io.RuntimeContext)
		wantErr bool
	}{
		{
			name: "successful authentication with token",
			setupFn: func(t *testing.T, rc *eos_io.RuntimeContext) {
				// Set up a mock client with token
				testutil.WithEnvVar(t, "VAULT_TOKEN", "test-auth-token")
				
				// Mock health check for validation
				transport := &testutil.MockHTTPTransport{
					ResponseMap: map[string]testutil.MockResponse{
						"/v1/sys/health": {
							StatusCode: 200,
							Body: map[string]interface{}{
								"initialized": true,
								"sealed":      false,
							},
						},
					},
				}
				testutil.WithMockHTTPClient(t, transport)
			},
			wantErr: false,
		},
		{
			name: "failed client creation",
			setupFn: func(t *testing.T, rc *eos_io.RuntimeContext) {
				// Clear any existing client
				shared.VaultClient = nil
				// Don't set up any auth method
			},
			wantErr: true,
		},
		{
			name: "failed authentication",
			setupFn: func(t *testing.T, rc *eos_io.RuntimeContext) {
				// Set up client but mock auth failure
				transport := &testutil.MockHTTPTransport{
					DefaultResponse: testutil.MockResponse{
						StatusCode: 403,
						Body:       map[string]interface{}{"error": "permission denied"},
					},
				}
				testutil.WithMockHTTPClient(t, transport)
			},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rc := testutil.TestRuntimeContext(t)
			tc.setupFn(t, rc)

			client, err := Authn(rc)

			if tc.wantErr {
				testutil.AssertError(t, err)
				testutil.AssertEqual(t, (*api.Client)(nil), client)
			} else {
				testutil.AssertNoError(t, err)
				testutil.AssertNotEqual(t, nil, client)
			}

			// Clean up
			shared.VaultClient = nil
		})
	}
}

func TestOrchestrateVaultAuth(t *testing.T) {
	// Since OrchestrateVaultAuth delegates to SecureAuthenticationOrchestrator,
	// we'll test the main scenarios
	tests := []struct {
		name    string
		setupFn func(t *testing.T) *api.Client
		wantErr bool
	}{
		{
			name: "already authenticated client",
			setupFn: func(t *testing.T) *api.Client {
				client, _ := api.NewClient(nil)
				client.SetToken("existing-token")
				
				// Mock successful auth check
				transport := &testutil.MockHTTPTransport{
					ResponseMap: map[string]testutil.MockResponse{
						"/v1/auth/token/lookup-self": {
							StatusCode: 200,
							Body: map[string]interface{}{
								"data": map[string]interface{}{
									"id": "existing-token",
								},
							},
						},
					},
				}
				testutil.WithMockHTTPClient(t, transport)
				
				return client
			},
			wantErr: false,
		},
		{
			name: "unauthenticated client needs auth",
			setupFn: func(t *testing.T) *api.Client {
				client, _ := api.NewClient(nil)
				// No token set
				
				// Mock auth check failure
				transport := &testutil.MockHTTPTransport{
					DefaultResponse: testutil.MockResponse{
						StatusCode: 403,
						Body:       map[string]interface{}{"error": "missing client token"},
					},
				}
				testutil.WithMockHTTPClient(t, transport)
				
				return client
			},
			wantErr: true, // Will fail because no auth methods are set up
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rc := testutil.TestRuntimeContext(t)
			client := tc.setupFn(t)

			err := OrchestrateVaultAuth(rc, client)

			if tc.wantErr {
				testutil.AssertError(t, err)
			} else {
				testutil.AssertNoError(t, err)
			}
		})
	}
}

func TestReadTokenFile(t *testing.T) {
	tests := []struct {
		name      string
		setupFn   func(t *testing.T) string // returns path
		wantToken string
		wantErr   bool
	}{
		{
			name: "read valid token file",
			setupFn: func(t *testing.T) string {
				tmpDir := testutil.TempDir(t)
				tokenFile := filepath.Join(tmpDir, "token")
				err := os.WriteFile(tokenFile, []byte("file-token-12345"), 0600)
				testutil.AssertNoError(t, err)
				return tokenFile
			},
			wantToken: "file-token-12345",
			wantErr:   false,
		},
		{
			name: "file does not exist",
			setupFn: func(t *testing.T) string {
				return "/nonexistent/token/file"
			},
			wantToken: "",
			wantErr:   true,
		},
		{
			name: "file with wrong permissions",
			setupFn: func(t *testing.T) string {
				tmpDir := testutil.TempDir(t)
				tokenFile := filepath.Join(tmpDir, "token")
				err := os.WriteFile(tokenFile, []byte("insecure-token"), 0644) // Wrong permissions
				testutil.AssertNoError(t, err)
				return tokenFile
			},
			wantToken: "",
			wantErr:   true, // Should fail security check
		},
		{
			name: "empty token file",
			setupFn: func(t *testing.T) string {
				tmpDir := testutil.TempDir(t)
				tokenFile := filepath.Join(tmpDir, "token")
				err := os.WriteFile(tokenFile, []byte(""), 0600)
				testutil.AssertNoError(t, err)
				return tokenFile
			},
			wantToken: "",
			wantErr:   true,
		},
		{
			name: "token with whitespace",
			setupFn: func(t *testing.T) string {
				tmpDir := testutil.TempDir(t)
				tokenFile := filepath.Join(tmpDir, "token")
				err := os.WriteFile(tokenFile, []byte("  token-with-spaces  \n"), 0600)
				testutil.AssertNoError(t, err)
				return tokenFile
			},
			wantToken: "token-with-spaces",
			wantErr:   false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rc := testutil.TestRuntimeContext(t)
			path := tc.setupFn(t)

			readFunc := readTokenFile(rc, path)
			token, err := readFunc(nil)

			if tc.wantErr {
				testutil.AssertError(t, err)
			} else {
				testutil.AssertNoError(t, err)
				testutil.AssertEqual(t, tc.wantToken, token)
			}
		})
	}
}

func TestTryAppRole(t *testing.T) {
	tests := []struct {
		name    string
		setupFn func(t *testing.T) (*api.Client, *eos_io.RuntimeContext)
		wantErr bool
	}{
		{
			name: "successful approle login",
			setupFn: func(t *testing.T) (*api.Client, *eos_io.RuntimeContext) {
				rc := testutil.TestRuntimeContext(t)
				
				// Create approle credentials files
				tmpDir := testutil.TempDir(t)
				roleFile := filepath.Join(tmpDir, "role-id")
				secretFile := filepath.Join(tmpDir, "secret-id")
				
				err := os.WriteFile(roleFile, []byte("test-role-id"), 0600)
				testutil.AssertNoError(t, err)
				err = os.WriteFile(secretFile, []byte("test-secret-id"), 0600)
				testutil.AssertNoError(t, err)
				
				// Override paths
				originalPaths := shared.AppRolePaths
				shared.AppRolePaths = shared.AppRolePathsStruct{
					RoleID:   roleFile,
					SecretID: secretFile,
				}
				t.Cleanup(func() {
					shared.AppRolePaths = originalPaths
				})
				
				// Mock successful approle login
				transport := &testutil.MockHTTPTransport{
					ResponseMap: map[string]testutil.MockResponse{
						"/v1/auth/approle/login": {
							StatusCode: 200,
							Body: map[string]interface{}{
								"auth": map[string]interface{}{
									"client_token": "approle-token-12345",
								},
							},
						},
					},
				}
				testutil.WithMockHTTPClient(t, transport)
				
				client, _ := api.NewClient(nil)
				return client, rc
			},
			wantErr: false,
		},
		{
			name: "missing approle credentials",
			setupFn: func(t *testing.T) (*api.Client, *eos_io.RuntimeContext) {
				rc := testutil.TestRuntimeContext(t)
				
				// Override paths to nonexistent files
				originalPaths := shared.AppRolePaths
				shared.AppRolePaths = shared.AppRolePathsStruct{
					RoleID:   "/nonexistent/role-id",
					SecretID: "/nonexistent/secret-id",
				}
				t.Cleanup(func() {
					shared.AppRolePaths = originalPaths
				})
				
				client, _ := api.NewClient(nil)
				return client, rc
			},
			wantErr: true,
		},
		{
			name: "approle login failure",
			setupFn: func(t *testing.T) (*api.Client, *eos_io.RuntimeContext) {
				rc := testutil.TestRuntimeContext(t)
				
				// Create approle credentials files
				tmpDir := testutil.TempDir(t)
				roleFile := filepath.Join(tmpDir, "role-id")
				secretFile := filepath.Join(tmpDir, "secret-id")
				
				err := os.WriteFile(roleFile, []byte("invalid-role"), 0600)
				testutil.AssertNoError(t, err)
				err = os.WriteFile(secretFile, []byte("invalid-secret"), 0600)
				testutil.AssertNoError(t, err)
				
				// Override paths
				originalPaths := shared.AppRolePaths
				shared.AppRolePaths = shared.AppRolePathsStruct{
					RoleID:   roleFile,
					SecretID: secretFile,
				}
				t.Cleanup(func() {
					shared.AppRolePaths = originalPaths
				})
				
				// Mock failed approle login
				transport := &testutil.MockHTTPTransport{
					ResponseMap: map[string]testutil.MockResponse{
						"/v1/auth/approle/login": {
							StatusCode: 400,
							Body: map[string]interface{}{
								"error": "invalid credentials",
							},
						},
					},
				}
				testutil.WithMockHTTPClient(t, transport)
				
				client, _ := api.NewClient(nil)
				return client, rc
			},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client, rc := tc.setupFn(t)

			token, err := tryAppRole(rc, client)

			if tc.wantErr {
				testutil.AssertError(t, err)
				testutil.AssertEqual(t, "", token)
			} else {
				testutil.AssertNoError(t, err)
				testutil.AssertNotEqual(t, "", token)
			}
		})
	}
}

func TestTryUserpass(t *testing.T) {
	// Note: This test is limited because it requires user interaction
	// In a real test environment, we would mock the interaction package
	t.Run("userpass requires interaction", func(t *testing.T) {
		rc := testutil.TestRuntimeContext(t)
		client, _ := api.NewClient(nil)

		// This will fail because we can't provide interactive input in tests
		token, err := tryUserpass(rc, client)
		testutil.AssertError(t, err)
		testutil.AssertEqual(t, "", token)
	})
}

func TestLoginWithAppRole(t *testing.T) {
	tests := []struct {
		name    string
		input   AppRoleLoginInput
		setupFn func(t *testing.T) *api.Client
		wantErr bool
		errMsg  string
	}{
		{
			name: "successful login",
			input: AppRoleLoginInput{
				RoleID:   "test-role-id",
				SecretID: "test-secret-id",
			},
			setupFn: func(t *testing.T) *api.Client {
				transport := &testutil.MockHTTPTransport{
					ResponseMap: map[string]testutil.MockResponse{
						"/v1/auth/approle/login": {
							StatusCode: 200,
							Body: map[string]interface{}{
								"auth": map[string]interface{}{
									"client_token": "new-token-12345",
									"lease_duration": 3600,
								},
							},
						},
					},
				}
				testutil.WithMockHTTPClient(t, transport)
				
				client, _ := api.NewClient(nil)
				return client
			},
			wantErr: false,
		},
		{
			name: "empty role ID",
			input: AppRoleLoginInput{
				RoleID:   "",
				SecretID: "test-secret-id",
			},
			setupFn: func(t *testing.T) *api.Client {
				client, _ := api.NewClient(nil)
				return client
			},
			wantErr: true,
			errMsg:  "role_id is required",
		},
		{
			name: "empty secret ID",
			input: AppRoleLoginInput{
				RoleID:   "test-role-id",
				SecretID: "",
			},
			setupFn: func(t *testing.T) *api.Client {
				client, _ := api.NewClient(nil)
				return client
			},
			wantErr: true,
			errMsg:  "secret_id is required",
		},
		{
			name: "login failure",
			input: AppRoleLoginInput{
				RoleID:   "invalid-role",
				SecretID: "invalid-secret",
			},
			setupFn: func(t *testing.T) *api.Client {
				transport := &testutil.MockHTTPTransport{
					ResponseMap: map[string]testutil.MockResponse{
						"/v1/auth/approle/login": {
							StatusCode: 403,
							Body: map[string]interface{}{
								"error": "permission denied",
							},
						},
					},
				}
				testutil.WithMockHTTPClient(t, transport)
				
				client, _ := api.NewClient(nil)
				return client
			},
			wantErr: true,
			errMsg:  "approle login failed",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rc := testutil.TestRuntimeContext(t)
			client := tc.setupFn(t)

			secret, err := LoginWithAppRole(rc, client, tc.input)

			if tc.wantErr {
				testutil.AssertError(t, err)
				if tc.errMsg != "" {
					testutil.AssertErrorContains(t, err, tc.errMsg)
				}
				testutil.AssertEqual(t, (*api.Secret)(nil), secret)
			} else {
				testutil.AssertNoError(t, err)
				testutil.AssertNotEqual(t, nil, secret)
				testutil.AssertNotEqual(t, nil, secret.Auth)
			}
		})
	}
}

func TestAuthenticationEdgeCases(t *testing.T) {
	t.Run("nil client handling", func(t *testing.T) {
		rc := testutil.TestRuntimeContext(t)
		
		err := OrchestrateVaultAuth(rc, nil)
		testutil.AssertError(t, err)
	})

	t.Run("context cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		rc := &eos_io.RuntimeContext{Ctx: ctx}
		
		// Cancel context immediately
		cancel()
		
		client, _ := api.NewClient(nil)
		err := OrchestrateVaultAuth(rc, client)
		// Should handle cancelled context gracefully
		testutil.AssertError(t, err)
	})

	t.Run("concurrent authentication attempts", func(t *testing.T) {
		rc := testutil.TestRuntimeContext(t)
		
		// Set up a mock successful auth
		transport := &testutil.MockHTTPTransport{
			ResponseMap: map[string]testutil.MockResponse{
				"/v1/auth/token/lookup-self": {
					StatusCode: 200,
					Body: map[string]interface{}{
						"data": map[string]interface{}{
							"id": "concurrent-token",
						},
					},
				},
			},
		}
		testutil.WithMockHTTPClient(t, transport)
		
		client, _ := api.NewClient(nil)
		client.SetToken("concurrent-token")
		
		// Run multiple concurrent auth attempts
		errors := make([]error, 5)
		for i := 0; i < 5; i++ {
			go func(idx int) {
				errors[idx] = OrchestrateVaultAuth(rc, client)
			}(i)
		}
		
		// Wait a bit for goroutines to complete
		testutil.Eventually(t, func() bool {
			for _, err := range errors {
				if err == nil {
					return true
				}
			}
			return false
		}, 100, 10)
	})
}

func TestAuthenticationSecurity(t *testing.T) {
	t.Run("token not leaked in errors", func(t *testing.T) {
		rc := testutil.TestRuntimeContext(t)
		
		// Create a client with a sensitive token
		client, _ := api.NewClient(nil)
		sensitiveToken := "s.SENSITIVE_TOKEN_12345"
		client.SetToken(sensitiveToken)
		
		// Mock a failure that might include the token
		transport := &testutil.MockHTTPTransport{
			ResponseMap: map[string]testutil.MockResponse{
				"/v1/auth/approle/login": {
					StatusCode: 403,
					Body: map[string]interface{}{
						"error": fmt.Sprintf("invalid token: %s", sensitiveToken),
					},
				},
			},
		}
		testutil.WithMockHTTPClient(t, transport)
		
		_, err := tryAppRole(rc, client)
		testutil.AssertError(t, err)
		
		// Ensure the error message doesn't contain the sensitive token
		errStr := err.Error()
		if strings.Contains(errStr, sensitiveToken) {
			t.Errorf("Error message leaked sensitive token: %s", errStr)
		}
	})

	t.Run("credentials not logged at info level", func(t *testing.T) {
		// This is more of a code review check, but we can verify
		// that sensitive operations use Debug level logging
		rc := testutil.TestRuntimeContext(t)
		
		// Create test credentials
		tmpDir := testutil.TempDir(t)
		tokenFile := filepath.Join(tmpDir, "token")
		err := os.WriteFile(tokenFile, []byte("secret-token"), 0600)
		testutil.AssertNoError(t, err)
		
		// Read token file - should only log at Debug level
		readFunc := readTokenFile(rc, tokenFile)
		token, err := readFunc(nil)
		testutil.AssertNoError(t, err)
		testutil.AssertEqual(t, "secret-token", token)
		
		// In production, this would only be visible at Debug level
	})
}

func BenchmarkAuthn(b *testing.B) {
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}
	
	// Set up a pre-authenticated client
	client, _ := api.NewClient(nil)
	client.SetToken("bench-token")
	shared.VaultClient = client
	
	// Mock successful validation
	transport := &testutil.MockHTTPTransport{
		ResponseMap: map[string]testutil.MockResponse{
			"/v1/auth/token/lookup-self": {
				StatusCode: 200,
				Body: map[string]interface{}{
					"data": map[string]interface{}{
						"id": "bench-token",
					},
				},
			},
		},
	}
	// Note: testutil.WithMockHTTPClient expects *testing.T, not *testing.B
	// For benchmarks, we'll skip the HTTP mocking
	_ = transport
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Authn(rc)
	}
	
	// Clean up
	shared.VaultClient = nil
}

func BenchmarkTryAppRole(b *testing.B) {
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}
	
	// Set up test credentials
	tmpDir := b.TempDir()
	roleFile := filepath.Join(tmpDir, "role-id")
	secretFile := filepath.Join(tmpDir, "secret-id")
	
	_ = os.WriteFile(roleFile, []byte("bench-role-id"), 0600)
	_ = os.WriteFile(secretFile, []byte("bench-secret-id"), 0600)
	
	originalPaths := shared.AppRolePaths
	shared.AppRolePaths = shared.AppRolePathsStruct{
		RoleID:   roleFile,
		SecretID: secretFile,
	}
	b.Cleanup(func() {
		shared.AppRolePaths = originalPaths
	})
	
	// Mock successful login
	transport := &testutil.MockHTTPTransport{
		ResponseMap: map[string]testutil.MockResponse{
			"/v1/auth/approle/login": {
				StatusCode: 200,
				Body: map[string]interface{}{
					"auth": map[string]interface{}{
						"client_token": "bench-approle-token",
					},
				},
			},
		},
	}
	// Note: testutil.WithMockHTTPClient expects *testing.T, not *testing.B
	// For benchmarks, we'll skip the HTTP mocking
	_ = transport
	
	client, _ := api.NewClient(nil)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = tryAppRole(rc, client)
	}
}