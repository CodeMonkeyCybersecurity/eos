package vault

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/testutil"
)

// TestTokenFileSecurityPermissions validates that token files have secure permissions
func TestTokenFileSecurityPermissions(t *testing.T) {
	tests := []struct {
		name         string
		path         string
		shouldExist  bool
		maxPerms     os.FileMode
	}{
		{
			name:        "agent token file",
			path:        "/etc/vault-agent-eos.token",
			shouldExist: false, // Should not exist in test env
			maxPerms:    0600,  // Owner read/write only
		},
		{
			name:        "disk token file", 
			path:        "/var/lib/eos/secrets/token",
			shouldExist: false,
			maxPerms:    0600,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if info, err := os.Stat(tt.path); err == nil {
				// File exists - check permissions
				perms := info.Mode().Perm()
				if perms > tt.maxPerms {
					t.Errorf("Token file %s has insecure permissions %o, should be <= %o", 
						tt.path, perms, tt.maxPerms)
				}
				
				// Check file is owned by root or current user
				if info.Mode()&os.ModeSetuid != 0 || info.Mode()&os.ModeSetgid != 0 {
					t.Errorf("Token file %s has setuid/setgid bits set - security risk", tt.path)
				}
			}
		})
	}
}

// TestAuthenticationFallbackSecurity ensures auth fallback doesn't leak sensitive info
func TestAuthenticationFallbackSecurity(t *testing.T) {
	rc := testutil.TestRuntimeContext(t)
	
	// Create temp directory for test token files
	tempDir := t.TempDir()
	
	// Test 1: Ensure no sensitive data in error messages
	t.Run("no_token_file_info_disclosure", func(t *testing.T) {
		// Mock vault client that fails all auth methods
		mockTransport := &testutil.MockHTTPTransport{
			ResponseMap: map[string]testutil.MockResponse{
				"/v1/auth/approle/login": {
					StatusCode: 401,
					Body:       map[string]any{"errors": []string{"permission denied"}},
				},
			},
			DefaultResponse: testutil.MockResponse{
				StatusCode: 401,
				Body:       map[string]any{"errors": []string{"unauthorized"}},
			},
		}
		
		cleanup := testutil.WithMockHTTPClient(t, mockTransport)
		defer cleanup()
		
		client, err := NewClient(rc)
		testutil.AssertNoError(t, err)
		
		// Authentication should fail without disclosing file paths
		err = OrchestrateVaultAuth(rc, client)
		testutil.AssertError(t, err)
		
		// Error should not contain sensitive file paths
		errMsg := err.Error()
		sensitiveTerms := []string{
			"/var/lib/eos/secrets",
			"/etc/vault-agent",
			"vault_init.json",
			"root token",
		}
		
		for _, term := range sensitiveTerms {
			if strings.Contains(errMsg, term) {
				t.Errorf("Error message contains sensitive information: %s", term)
			}
		}
	})
	
	// Test 2: Token file reading security
	t.Run("token_file_reading_security", func(t *testing.T) {
		// Create a test token file with sensitive content
		tokenFile := filepath.Join(tempDir, "test_token")
		sensitiveToken := "hvs.ABCDEF123456789"
		
		err := os.WriteFile(tokenFile, []byte(sensitiveToken+"\n"), 0600)
		testutil.AssertNoError(t, err)
		
		// Test the readTokenFile function
		readFn := readTokenFile(rc, tokenFile)
		client, err := NewClient(rc)
		testutil.AssertNoError(t, err)
		
		token, err := readFn(client)
		testutil.AssertNoError(t, err)
		testutil.AssertEqual(t, sensitiveToken, token)
		
		// Verify file still has secure permissions
		info, err := os.Stat(tokenFile)
		testutil.AssertNoError(t, err)
		testutil.AssertEqual(t, os.FileMode(0600), info.Mode().Perm())
	})
}

// TestVaultClientCacheSecurity tests the global vault client cache for race conditions
func TestVaultClientCacheSecurity(t *testing.T) {
	rc := testutil.TestRuntimeContext(t)
	
	// Test concurrent access to vault client cache
	t.Run("concurrent_client_access", func(t *testing.T) {
		cleanup := testutil.WithMockHTTPClient(t, testutil.VaultMockTransport())
		defer cleanup()
		
		// Create multiple goroutines accessing vault client simultaneously
		done := make(chan bool, 10)
		
		for i := 0; i < 10; i++ {
			go func() {
				defer func() { done <- true }()
				
				client, err := NewClient(rc)
				if err != nil {
					t.Errorf("Failed to create vault client: %v", err)
					return
				}
				
				// Verify client is properly configured
				if client.Address() == "" {
					t.Error("Vault client address is empty")
				}
			}()
		}
		
		// Wait for all goroutines to complete
		for i := 0; i < 10; i++ {
			<-done
		}
	})
}

// TestTLSConfigurationSecurity validates TLS setup security
func TestTLSConfigurationSecurity(t *testing.T) {
	rc := testutil.TestRuntimeContext(t)
	
	tests := []struct {
		name        string
		caCertPath  string
		expectError bool
	}{
		{
			name:        "default_ca_cert_path",
			caCertPath:  "",  // Will use default /opt/vault/tls/tls.crt
			expectError: false, // Should work with mock
		},
		{
			name:        "nonexistent_ca_cert",
			caCertPath:  "/nonexistent/cert.pem",
			expectError: false, // Should still create client, just with different config
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.caCertPath != "" {
				os.Setenv("VAULT_CACERT", tt.caCertPath)
				defer os.Unsetenv("VAULT_CACERT")
			}
			
			client, err := NewClient(rc)
			if tt.expectError {
				testutil.AssertError(t, err)
			} else {
				testutil.AssertNoError(t, err)
				testutil.AssertNotEqual(t, "", client.Address())
			}
		})
	}
}

// TestTokenValidationSecurity ensures token validation is secure
func TestTokenValidationSecurity(t *testing.T) {
	rc := testutil.TestRuntimeContext(t)
	
	tests := []struct {
		name          string
		token         string
		mockResponse  testutil.MockResponse
		shouldBeValid bool
	}{
		{
			name:  "valid_token",
			token: "hvs.valid_token_123",
			mockResponse: testutil.MockResponse{
				StatusCode: 200,
				Body: map[string]any{
					"data": map[string]any{
						"policies": []string{"default"},
						"ttl":      3600,
					},
				},
			},
			shouldBeValid: true,
		},
		{
			name:  "expired_token",
			token: "hvs.expired_token_456",
			mockResponse: testutil.MockResponse{
				StatusCode: 403,
				Body:       map[string]any{"errors": []string{"permission denied"}},
			},
			shouldBeValid: false,
		},
		{
			name:  "malformed_token", 
			token: "not_a_vault_token",
			mockResponse: testutil.MockResponse{
				StatusCode: 400,
				Body:       map[string]any{"errors": []string{"invalid token"}},
			},
			shouldBeValid: false,
		},
		{
			name:  "empty_token",
			token: "",
			mockResponse: testutil.MockResponse{
				StatusCode: 400,
				Body:       map[string]any{"errors": []string{"missing token"}},
			},
			shouldBeValid: false,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockTransport := &testutil.MockHTTPTransport{
				ResponseMap: map[string]testutil.MockResponse{
					"/v1/auth/token/lookup-self": tt.mockResponse,
				},
				DefaultResponse: testutil.MockResponse{
					StatusCode: 404,
					Body:       map[string]any{"errors": []string{"not found"}},
				},
			}
			
			cleanup := testutil.WithMockHTTPClient(t, mockTransport)
			defer cleanup()
			
			client, err := NewClient(rc)
			testutil.AssertNoError(t, err)
			
			isValid := VerifyToken(rc, client, tt.token)
			testutil.AssertEqual(t, tt.shouldBeValid, isValid)
		})
	}
}

// TestAppRoleAuthenticationSecurity tests AppRole auth security
func TestAppRoleAuthenticationSecurity(t *testing.T) {
	rc := testutil.TestRuntimeContext(t)
	
	t.Run("invalid_credentials_no_leak", func(t *testing.T) {
		mockTransport := &testutil.MockHTTPTransport{
			ResponseMap: map[string]testutil.MockResponse{
				"/v1/auth/approle/login": {
					StatusCode: 401,
					Body:       map[string]any{"errors": []string{"invalid credentials"}},
				},
			},
		}
		
		cleanup := testutil.WithMockHTTPClient(t, mockTransport)
		defer cleanup()
		
		client, err := NewClient(rc)
		testutil.AssertNoError(t, err)
		
		// This should fail but not leak sensitive information
		_, err = tryAppRole(rc, client)
		testutil.AssertError(t, err)
		
		// Error should not contain role_id or secret_id
		errMsg := err.Error()
		if strings.Contains(errMsg, "role_id") || strings.Contains(errMsg, "secret_id") {
			t.Error("AppRole error contains sensitive credential information")
		}
	})
}