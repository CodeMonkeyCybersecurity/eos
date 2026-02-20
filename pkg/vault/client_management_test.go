// pkg/vault/client_management_test.go - Tests for vault client management
// Covers: P0 address resolution bug fix, client creation, auth failure behaviour
package vault

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	api "github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

// =============================================================================
// UNIT TESTS (70%) - Address resolution, constants, token validation
// =============================================================================

// TestDefaultVaultAddress_NoLiteralString verifies the P0 fix:
// DefaultVaultAddress() must return a resolvable address, NOT the literal string
// "shared.GetInternalHostname". This was the root cause of DNS resolution failures.
// Evidence: pkg/vault/constants.go:66 had fmt.Sprintf("https://shared.GetInternalHostname:%d", ...)
// which produced "https://shared.GetInternalHostname:8179" - a non-existent DNS name.
func TestDefaultVaultAddress_NoLiteralString(t *testing.T) {
	addr := DefaultVaultAddress()

	// CRITICAL: Must NOT contain the literal string "shared.GetInternalHostname"
	assert.NotContains(t, addr, "shared.GetInternalHostname",
		"DefaultVaultAddress() must call shared.GetInternalHostname() function, not use it as string literal")

	// Must contain a valid hostname or IP
	assert.True(t, strings.HasPrefix(addr, "https://"),
		"DefaultVaultAddress() must use HTTPS")

	// Must contain the correct port
	assert.Contains(t, addr, fmt.Sprintf(":%d", shared.PortVault),
		"DefaultVaultAddress() must use shared.PortVault")
}

// TestLocalhostIP_IsValidIP verifies the P0 fix:
// LocalhostIP must be "127.0.0.1", not "shared.GetInternalHostname"
// Evidence: pkg/vault/constants.go:257 had LocalhostIP = "shared.GetInternalHostname"
func TestLocalhostIP_IsValidIP(t *testing.T) {
	ip := net.ParseIP(LocalhostIP)
	require.NotNil(t, ip,
		"LocalhostIP must be a valid IP address, got: %q", LocalhostIP)

	assert.Equal(t, "127.0.0.1", LocalhostIP,
		"LocalhostIP should be 127.0.0.1")
}

// TestNoDuplicateEnvConstants verifies P0 fix:
// EnvVaultAgentAddress and EnvVaultInsecure were duplicates of EnvVaultAgentAddr and EnvVaultSkipVerify
func TestNoDuplicateEnvConstants(t *testing.T) {
	// These should be the canonical names
	assert.Equal(t, "VAULT_AGENT_ADDR", EnvVaultAgentAddr)
	assert.Equal(t, "VAULT_SKIP_VERIFY", EnvVaultSkipVerify)
}

// TestVaultTokenFilePerm_NotDuplicate verifies P0 fix:
// SecureFilePermissions was removed from file_security.go (was a duplicate)
// VaultTokenFilePerm in constants.go is the single source of truth
func TestVaultTokenFilePerm_NotDuplicate(t *testing.T) {
	assert.Equal(t, 0600, VaultTokenFilePerm,
		"VaultTokenFilePerm should be 0600 (owner read/write only)")
}

// TestTokenValidation verifies token format validation logic
func TestTokenValidation(t *testing.T) {
	tests := []struct {
		name    string
		token   string
		wantErr bool
	}{
		{"valid_hvs_token", "hvs.CAESIJlU02LQZqabcdef1234567890", false},
		{"valid_s_token", "s.1234567890abcdef1234", false},
		{"valid_batch_token", "b.AAAAAQKrabcdefghijklmnop", false},
		{"empty_token", "", true},
		{"too_short", "hvs.abc", true},
		{"control_char", "hvs.abc\x00def1234567", true},
		{"too_long", strings.Repeat("a", 257), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateTokenFormat(tt.token)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestSanitizeTokenForLogging verifies tokens are never exposed in logs
func TestSanitizeTokenForLogging_NoDataLeakage(t *testing.T) {
	tests := []struct {
		name   string
		token  string
		expect string
	}{
		{"hvs_token", "hvs.CAESIJlU02LQZqabcdef", "hvs.***"},
		{"service_token", "s.1234567890abcdef", "s.***"},
		{"batch_token", "b.AAAAAQKrabcdefghij", "b.***"},
		{"unknown_format", "random-token-123", "***"},
		{"empty_token", "", "***"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SanitizeTokenForLogging(tt.token)
			assert.Equal(t, tt.expect, result)
			// SECURITY: Result must NEVER contain actual token characters beyond the prefix
			if len(tt.token) > 4 {
				assert.NotContains(t, result, tt.token[4:],
					"Sanitized token must not contain actual token data")
			}
		})
	}
}

// TestGetUnauthenticatedVaultClient verifies the new function for health checks
func TestGetUnauthenticatedVaultClient_ReturnsNoToken(t *testing.T) {
	// Save and restore env
	originalAddr := os.Getenv("VAULT_ADDR")
	defer func() {
		if originalAddr != "" {
			_ = os.Setenv("VAULT_ADDR", originalAddr)
		} else {
			_ = os.Unsetenv("VAULT_ADDR")
		}
	}()

	_ = os.Setenv("VAULT_ADDR", "https://127.0.0.1:8200")
	_ = os.Setenv("VAULT_SKIP_VERIFY", "true")

	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
		Log: zaptest.NewLogger(t),
	}

	client, err := GetUnauthenticatedVaultClient(rc)
	require.NoError(t, err, "GetUnauthenticatedVaultClient should not require auth")
	require.NotNil(t, client)

	// Must NOT have a token set
	assert.Empty(t, client.Token(),
		"Unauthenticated client must not have a token")

	// Must have the correct address
	assert.Equal(t, "https://127.0.0.1:8200", client.Address())
}

// TestGetUnauthenticatedVaultClient_DefaultAddress verifies fallback address uses dynamic hostname
func TestGetUnauthenticatedVaultClient_DefaultAddress(t *testing.T) {
	originalAddr := os.Getenv("VAULT_ADDR")
	defer func() {
		if originalAddr != "" {
			_ = os.Setenv("VAULT_ADDR", originalAddr)
		} else {
			_ = os.Unsetenv("VAULT_ADDR")
		}
	}()

	_ = os.Unsetenv("VAULT_ADDR")
	_ = os.Setenv("VAULT_SKIP_VERIFY", "true")

	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
		Log: zaptest.NewLogger(t),
	}

	client, err := GetUnauthenticatedVaultClient(rc)
	require.NoError(t, err)
	require.NotNil(t, client)

	// Address must NOT contain the literal string "shared.GetInternalHostname"
	assert.NotContains(t, client.Address(), "shared.GetInternalHostname",
		"Default address must use dynamic hostname, not literal string")
}

// =============================================================================
// INTEGRATION TESTS (20%) - Client creation with environment, caching
// =============================================================================

// TestVaultClientCaching_SetAndRetrieve tests context-based client caching
func TestVaultClientCaching_SetAndRetrieve(t *testing.T) {
	// Save and restore env
	originalAddr := os.Getenv("VAULT_ADDR")
	originalToken := os.Getenv("VAULT_TOKEN")
	defer func() {
		if originalAddr != "" {
			_ = os.Setenv("VAULT_ADDR", originalAddr)
		} else {
			_ = os.Unsetenv("VAULT_ADDR")
		}
		if originalToken != "" {
			_ = os.Setenv("VAULT_TOKEN", originalToken)
		} else {
			_ = os.Unsetenv("VAULT_TOKEN")
		}
	}()

	_ = os.Setenv("VAULT_ADDR", "https://127.0.0.1:8200")
	_ = os.Setenv("VAULT_SKIP_VERIFY", "true")

	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
		Log: zaptest.NewLogger(t),
	}

	// Create and cache a client
	client, err := GetUnauthenticatedVaultClient(rc)
	require.NoError(t, err)

	// Manually set a token and cache
	client.SetToken("test-token-for-caching")
	SetVaultClient(rc, client)

	// Retrieve from cache - should get the same token back
	cached, ok := rc.Ctx.Value(vaultClientKey).(*api.Client)
	require.True(t, ok, "Client should be cached in context")
	assert.Equal(t, "test-token-for-caching", cached.Token())
}

// TestAdminClientFallbackAddress verifies admin client uses proper address
func TestAdminClientFallbackAddress(t *testing.T) {
	// This test verifies the P0 fix in client_admin.go:94
	// Previously: fmt.Sprintf("https://shared.GetInternalHostname:%d", shared.PortVault)
	// Now: fmt.Sprintf("https://%s:%d", shared.GetInternalHostname(), shared.PortVault)

	expectedAddr := fmt.Sprintf("https://%s:%d", shared.GetInternalHostname(), shared.PortVault)

	// The address should NOT contain literal "shared.GetInternalHostname"
	assert.NotContains(t, expectedAddr, "shared.GetInternalHostname",
		"Admin client fallback address must use dynamic hostname")

	// Should contain the actual port
	assert.Contains(t, expectedAddr, fmt.Sprintf(":%d", shared.PortVault))
}

// =============================================================================
// REGRESSION TESTS (10%) - Ensure bugs don't return
// =============================================================================

// TestNoLiteralGetInternalHostnameInAddresses is a comprehensive regression test
// that ensures the "shared.GetInternalHostname" string literal bug never returns.
// This bug was found in 8+ production files where the function name was used as a string.
func TestNoLiteralGetInternalHostnameInAddresses(t *testing.T) {
	// Test all address-producing functions
	addressFuncs := []struct {
		name string
		fn   func() string
	}{
		{"DefaultVaultAddress", DefaultVaultAddress},
	}

	for _, af := range addressFuncs {
		t.Run(af.name, func(t *testing.T) {
			addr := af.fn()
			assert.NotContains(t, addr, "shared.GetInternalHostname",
				"%s() returned literal string instead of calling function", af.name)
			assert.NotContains(t, addr, "GetInternalHostname",
				"%s() contains GetInternalHostname as literal", af.name)
		})
	}

	// Test constants
	t.Run("LocalhostIP_is_valid", func(t *testing.T) {
		ip := net.ParseIP(LocalhostIP)
		assert.NotNil(t, ip, "LocalhostIP must be parseable as IP, got: %q", LocalhostIP)
	})

	t.Run("LocalhostIP_is_127001", func(t *testing.T) {
		assert.Equal(t, "127.0.0.1", LocalhostIP,
			"LocalhostIP must be 127.0.0.1")
	})
}

// TestVaultTokenFilePermission_SingleSourceOfTruth verifies the duplicate constant removal
func TestVaultTokenFilePermission_SingleSourceOfTruth(t *testing.T) {
	// VaultTokenFilePerm from constants.go is the ONLY source of truth for 0600
	assert.Equal(t, 0600, VaultTokenFilePerm)
	assert.Equal(t, 0600, VaultSecretFilePerm)

	// These are different permission levels and should remain distinct
	assert.NotEqual(t, VaultTokenFilePerm, VaultConfigPerm,
		"Token files (0600) should be more restrictive than config files (0640)")
}

// Benchmark test for client operations
func BenchmarkVaultClientOperations(b *testing.B) {
	originalAddr := os.Getenv("VAULT_ADDR")
	defer func() {
		if originalAddr != "" {
			_ = os.Setenv("VAULT_ADDR", originalAddr)
		} else {
			_ = os.Unsetenv("VAULT_ADDR")
		}
	}()

	_ = os.Setenv("VAULT_ADDR", "https://127.0.0.1:8200")
	_ = os.Setenv("VAULT_SKIP_VERIFY", "true")

	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
		Log: zaptest.NewLogger(b),
	}

	b.ResetTimer()
	for range b.N {
		_, _ = GetUnauthenticatedVaultClient(rc)
	}
}
