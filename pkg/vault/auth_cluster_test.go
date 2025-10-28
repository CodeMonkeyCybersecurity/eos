package vault

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// ============================================================================
// Token Sanitization Tests (P0 Issue #1 Fix)
// ============================================================================

func TestSanitizeTokenForLogging(t *testing.T) {
	tests := []struct {
		name     string
		token    string
		expected string
	}{
		{
			name:     "HVAC token (hvs. prefix)",
			token:    "hvs.CAESIJlU02LQZqEhq1TgQfeQYY",
			expected: "hvs.***",
		},
		{
			name:     "Service token (s. prefix)",
			token:    "s.1234567890abcdef",
			expected: "s.***",
		},
		{
			name:     "Service token starting with s.12 (REGRESSION TEST - P0 Bug)",
			token:    "s.12xxxxxxxxxxxxxxxx",
			expected: "s.***", // MUST NOT be "s.12***"
		},
		{
			name:     "Service token starting with s.ab",
			token:    "s.abcdefghijklmnop",
			expected: "s.***",
		},
		{
			name:     "Batch token (b. prefix)",
			token:    "b.AAAAAQKrRpdJHXZ",
			expected: "b.***",
		},
		{
			name:     "Empty token",
			token:    "",
			expected: "***",
		},
		{
			name:     "Unknown format",
			token:    "unknown_token_format",
			expected: "***",
		},
		{
			name:     "Very short token",
			token:    "abc",
			expected: "***",
		},
		{
			name:     "Root token starting with s.r",
			token:    "s.root1234567890",
			expected: "s.***",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizeTokenForLogging(tt.token)
			assert.Equal(t, tt.expected, result,
				"Token %q should sanitize to %q but got %q",
				tt.token, tt.expected, result)

			// CRITICAL SECURITY ASSERTION: sanitized output must NOT contain token value
			if len(tt.token) > 4 {
				tokenValue := tt.token[4:] // Everything after prefix
				assert.NotContains(t, result, tokenValue,
					"SECURITY VIOLATION: Sanitized output contains token value characters")
			}

			// Verify we never expose more than type prefix
			if strings.HasPrefix(tt.token, "hvs.") {
				assert.Equal(t, "hvs.***", result, "HVAC tokens must only show 'hvs.***'")
			} else if strings.HasPrefix(tt.token, "s.") {
				assert.Equal(t, "s.***", result, "Service tokens must only show 's.***'")
			} else if strings.HasPrefix(tt.token, "b.") {
				assert.Equal(t, "b.***", result, "Batch tokens must only show 'b.***'")
			}
		})
	}
}

// ============================================================================
// Token Format Validation Tests
// ============================================================================

func TestValidateTokenFormat(t *testing.T) {
	tests := []struct {
		name    string
		token   string
		wantErr bool
		errMsg  string
	}{
		{
			name:    "Valid HVAC token",
			token:   "hvs.CAESIJlU02LQZqEhq1TgQfeQYY",
			wantErr: false,
		},
		{
			name:    "Valid service token",
			token:   "s.1234567890abcdefghijklmn",
			wantErr: false,
		},
		{
			name:    "Valid batch token",
			token:   "b.AAAAAQKrRpdJHXZVhmsTjoXKMuQ",
			wantErr: false,
		},
		{
			name:    "Control character (null byte) - INJECTION ATTACK",
			token:   "s.abc\x00xyz789",
			wantErr: true,
			errMsg:  "contains invalid character",
		},
		{
			name:    "Control character (newline) - INJECTION ATTACK",
			token:   "s.abc\nxyz789",
			wantErr: true,
			errMsg:  "contains invalid character",
		},
		{
			name:    "Control character (tab) - INJECTION ATTACK",
			token:   "s.abc\txyz789",
			wantErr: true,
			errMsg:  "contains invalid character",
		},
		{
			name:    "Control character (ESC) - INJECTION ATTACK",
			token:   "s.abc\x1bxyz789",
			wantErr: true,
			errMsg:  "contains invalid character",
		},
		{
			name:    "Too short (boundary test)",
			token:   "s.abc",
			wantErr: true,
			errMsg:  "token too short",
		},
		{
			name:    "Exactly 10 chars (boundary test)",
			token:   "s.12345678",
			wantErr: false,
		},
		{
			name:    "Too long (300 chars)",
			token:   "s." + generateString(300),
			wantErr: true,
			errMsg:  "token too long",
		},
		{
			name:    "Exactly 256 chars (boundary test)",
			token:   "s." + generateString(254),
			wantErr: false,
		},
		{
			name:    "Empty token",
			token:   "",
			wantErr: true,
			errMsg:  "token too short",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateTokenFormat(tt.token)

			if tt.wantErr {
				assert.Error(t, err, "Expected error for token: %q", tt.token)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg,
						"Error message should contain: %q", tt.errMsg)
				}
			} else {
				assert.NoError(t, err, "Expected no error for valid token: %q", tt.token)
			}
		})
	}
}

// ============================================================================
// TTL Duration Formatting Tests
// ============================================================================

func TestFormatTTLDuration(t *testing.T) {
	tests := []struct {
		name     string
		seconds  int64
		expected string
	}{
		{
			name:     "Less than 1 minute",
			seconds:  45,
			expected: "45s",
		},
		{
			name:     "Exactly 1 minute",
			seconds:  60,
			expected: "1m",
		},
		{
			name:     "Multiple minutes",
			seconds:  120,
			expected: "2m",
		},
		{
			name:     "Exactly 1 hour",
			seconds:  3600,
			expected: "1h",
		},
		{
			name:     "Hours and minutes",
			seconds:  3665, // 1h 1m 5s
			expected: "1h1m",
		},
		{
			name:     "Multiple hours",
			seconds:  7200,
			expected: "2h",
		},
		{
			name:     "Vault Agent default (4 hours)",
			seconds:  14400,
			expected: "4h",
		},
		{
			name:     "Very short TTL (boundary)",
			seconds:  1,
			expected: "1s",
		},
		{
			name:     "59 seconds (boundary)",
			seconds:  59,
			expected: "59s",
		},
		{
			name:     "59 minutes (boundary)",
			seconds:  3540, // 59m
			expected: "59m",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatTTLDuration(tt.seconds)
			assert.Equal(t, tt.expected, result,
				"%d seconds should format to %q but got %q",
				tt.seconds, tt.expected, result)
		})
	}
}

// ============================================================================
// Helper Functions
// ============================================================================

func generateString(length int) string {
	// Generate a string of specified length for testing
	result := make([]byte, length)
	for i := range result {
		result[i] = 'a'
	}
	return string(result)
}

// ============================================================================
// Integration Test Documentation
// ============================================================================

// The following functions require integration testing with a real Vault instance:
//
// • GetVaultClientWithToken()
//   - Requires: Running Vault server
//   - Tests: Token validation, seal status, TTL checking, capability verification
//   - Critical scenarios:
//     * Periodic token with low TTL (MUST ACCEPT)
//     * Non-periodic token with low TTL (MUST REJECT)
//     * Sealed vault (MUST REJECT before token validation)
//     * Orphan tokens (ACCEPT with warning)
//     * Missing capabilities on any of 4 paths (MUST REJECT)
//
// • verifyClusterOperationCapabilities()
//   - Requires: Running Vault server with test tokens
//   - Tests: All 4 capability paths checked, policy validation, TTL re-check
//   - Critical scenarios:
//     * Token expires during validation (race condition test)
//     * Token with partial capabilities (missing snapshot access)
//     * Revocation queue detection
//
// To run integration tests:
//   1. Start local Vault: vault server -dev
//   2. Export VAULT_ADDR=http://localhost:8200
//   3. go test -v ./pkg/vault/ -tags=integration
//
// Integration test coverage needed:
//   - P0 Issue #2 Fix: Periodic token with low TTL accepted
//   - P0 Issue #3 Fix: Orphan token warning
//   - P1 Issue #4 Fix: Race condition (TTL drops during validation)
//   - P1 Issue #6 Fix: All 4 capability paths checked
//
// These tests are documented here but not implemented due to requiring:
//   - Complex Vault API mocking (would need to mock api.Client interface)
//   - Multiple sequential API calls (seal status, token lookup, capabilities×4)
//   - State management across mock calls
//
// Alternative: Use github.com/hashicorp/vault/api/mock package (if available)
// or create integration test suite with real Vault in Docker.
