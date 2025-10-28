package vault

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"unicode"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/hashicorp/vault/api"
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

// TestSanitizeTokenForLogging_ExportedFunction tests that the exported version
// (SanitizeTokenForLogging) works identically to the internal version.
// P1 Issue #20 Fix: Verify exported function is usable from other packages.
func TestSanitizeTokenForLogging_ExportedFunction(t *testing.T) {
	testTokens := []string{
		"hvs.CAESIJlU02LQZqEhq1TgQfeQYY",
		"s.1234567890abcdef",
		"s.12xxxxxxxxxxxxxxxx", // Regression test case
		"b.AAAAAQKrRpdJHXZ",
		"",
		"unknown_token_format",
	}

	for _, token := range testTokens {
		t.Run("token="+token[:min(len(token), 10)], func(t *testing.T) {
			// Call both versions
			resultInternal := sanitizeTokenForLogging(token)
			resultExported := SanitizeTokenForLogging(token)

			// They must return identical results
			assert.Equal(t, resultInternal, resultExported,
				"Exported SanitizeTokenForLogging() returned %q but internal sanitizeTokenForLogging() returned %q (must be identical)",
				resultExported, resultInternal)

			// Verify neither exposes token value
			if len(token) > 4 {
				tokenValue := token[4:]
				assert.NotContains(t, resultExported, tokenValue,
					"Exported function SECURITY VIOLATION: Result contains token value")
				assert.NotContains(t, resultInternal, tokenValue,
					"Internal function SECURITY VIOLATION: Result contains token value")
			}
		})
	}
}

// min returns the minimum of two integers (helper for test)
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
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
// Log Sanitization Tests (P1 Issue #40, P2 Issue #43, P3 Issue #44 Fixes)
// ============================================================================

func TestSanitizeForLogging(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Normal printable string",
			input:    "hello world",
			expected: "hello world",
		},
		{
			name:     "String with newline (P2 Issue #43 - log injection)",
			input:    "innocent\nFAKE LOG ENTRY",
			expected: "innocent FAKE LOG ENTRY", // Newline replaced with space
		},
		{
			name:     "String with carriage return",
			input:    "line1\rline2",
			expected: "line1 line2", // CR replaced with space
		},
		{
			name:     "String with tab",
			input:    "col1\tcol2",
			expected: "col1 col2", // Tab replaced with space
		},
		{
			name:     "String with ANSI escape sequence",
			input:    "\x1b[31mRED TEXT\x1b[0m",
			expected: " [31mRED TEXT [0m", // ESC (27) replaced with space
		},
		{
			name:     "String with null byte",
			input:    "hello\x00world",
			expected: "hello world", // Null replaced with space
		},
		{
			name:     "String with DEL character",
			input:    "hello\x7fworld",
			expected: "hello world", // DEL replaced with space (unicode.IsControl catches it)
		},
		{
			name:     "String with multiple control characters",
			input:    "a\nb\rc\td\x00e\x1bf",
			expected: "a b c d e f", // All replaced with spaces
		},
		{
			name:     "Very long string (P3 Issue #44 - UTF-8 truncation)",
			input:    "a123456789b123456789c123456789d123456789e123456789f123456789g123456789h123456789i123456789j123456789k123456789",
			expected: "a123456789b123456789c123456789d123456789e123456789f123456789g123456789h123456789i123456789j123456789...[truncated]",
		},
		{
			name:     "UTF-8 multi-byte characters",
			input:    "Hello 世界 🌍",
			expected: "Hello 世界 🌍",
		},
		{
			name:     "Long UTF-8 string (truncation at rune boundary)",
			input:    "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789世界",
			expected: "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789...[truncated]",
		},
		{
			name:     "Empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "Only control characters",
			input:    "\n\r\t\x00\x1b",
			expected: "     ", // All replaced with spaces
		},
		{
			name:     "Exact 100 runes (no truncation)",
			input:    "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789",
			expected: "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789",
		},
		{
			name:     "Log injection attack simulation",
			input:    "malicious_value\n2025-01-28 INFO [vault] User admin authenticated successfully",
			expected: "malicious_value 2025-01-28 INFO [vault] User admin authenticated successfully",
		},
		// P2 Issue #48 & #50 Fix: Unicode control character tests
		{
			name:     "Unicode Line Separator U+2028 (P2 #48 - CRITICAL)",
			input:    "innocent\u2028FAKE LOG ENTRY",
			expected: "innocent FAKE LOG ENTRY", // U+2028 replaced with space
		},
		{
			name:     "Unicode Paragraph Separator U+2029",
			input:    "line1\u2029line2",
			expected: "line1 line2", // U+2029 replaced with space
		},
		{
			name:     "Unicode Zero-Width Space U+200B (invisible char)",
			input:    "hello\u200Bworld",
			expected: "hello world", // U+200B replaced with space
		},
		{
			name:     "Unicode Right-to-Left Override U+202E (bidi attack)",
			input:    "user\u202Eadmin",
			expected: "user admin", // U+202E replaced with space
		},
		{
			name:     "Unicode C1 Control U+0080",
			input:    "text\u0080here",
			expected: "text here", // U+0080 replaced with space
		},
		{
			name:     "Unicode BOM U+FEFF",
			input:    "\uFEFFBOM at start",
			expected: " BOM at start", // U+FEFF replaced with space
		},
		{
			name:     "Mixed ASCII and Unicode controls",
			input:    "a\nb\u2028c\td\u200Be",
			expected: "a b c d e", // All controls replaced with spaces
		},
		{
			name:     "Unicode non-breaking space U+00A0",
			input:    "word\u00A0word",
			expected: "word word", // U+00A0 normalized to regular space
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizeForLogging(tt.input)
			assert.Equal(t, tt.expected, result,
				"sanitizeForLogging(%q) = %q, expected %q", tt.input, result, tt.expected)

			// Additional security checks - ASCII control characters
			assert.NotContains(t, result, "\n", "Output should not contain newlines")
			assert.NotContains(t, result, "\r", "Output should not contain carriage returns")
			assert.NotContains(t, result, "\t", "Output should not contain tabs")
			assert.NotContains(t, result, "\x00", "Output should not contain null bytes")
			assert.NotContains(t, result, "\x1b", "Output should not contain ESC character")

			// P2 Issue #48 & #50 Fix: Unicode control character checks
			assert.NotContains(t, result, "\u2028", "Output should not contain Unicode Line Separator (U+2028)")
			assert.NotContains(t, result, "\u2029", "Output should not contain Unicode Paragraph Separator (U+2029)")
			assert.NotContains(t, result, "\u200B", "Output should not contain Zero-Width Space (U+200B)")
			assert.NotContains(t, result, "\u200C", "Output should not contain Zero-Width Non-Joiner (U+200C)")
			assert.NotContains(t, result, "\u200D", "Output should not contain Zero-Width Joiner (U+200D)")
			assert.NotContains(t, result, "\u202E", "Output should not contain Right-to-Left Override (U+202E)")
			assert.NotContains(t, result, "\uFEFF", "Output should not contain BOM (U+FEFF)")
			assert.NotContains(t, result, "\u0080", "Output should not contain C1 control (U+0080)")

			// Verify NO Unicode control characters remain (comprehensive check)
			for _, r := range result {
				assert.False(t, unicode.IsControl(r) && r != ' ',
					"Output should not contain control character: U+%04X", r)
			}

			// Check length constraint (P3 Issue #44)
			runes := []rune(result)
			if !strings.HasSuffix(result, "...[truncated]") {
				assert.LessOrEqual(t, len(runes), 100,
					"Output should be <= 100 runes (was %d)", len(runes))
			} else {
				// If truncated, should be exactly 100 + suffix
				withoutSuffix := strings.TrimSuffix(result, "...[truncated]")
				assert.Equal(t, 100, len([]rune(withoutSuffix)),
					"Truncated output should have exactly 100 runes before suffix")
			}
		})
	}
}

// ============================================================================
// Periodic Token Detection Tests (P0 Issue #12 Fix)
// ============================================================================

func TestIsPeriodicToken(t *testing.T) {
	tests := []struct {
		name     string
		secret   *api.Secret
		expected bool
	}{
		{
			name: "Periodic token with period > 0",
			secret: &api.Secret{
				Data: map[string]interface{}{
					"period": json.Number("14400"), // 4 hours
				},
			},
			expected: true,
		},
		{
			name: "Non-periodic token (period = 0)",
			secret: &api.Secret{
				Data: map[string]interface{}{
					"period": json.Number("0"),
				},
			},
			expected: false,
		},
		{
			name: "Token without period field",
			secret: &api.Secret{
				Data: map[string]interface{}{
					"ttl": json.Number("3600"),
				},
			},
			expected: false,
		},
		{
			name:     "Nil secret",
			secret:   nil,
			expected: false,
		},
		{
			name: "Secret with nil Data",
			secret: &api.Secret{
				Data: nil,
			},
			expected: false,
		},
		{
			name: "Period field with wrong type (not json.Number)",
			secret: &api.Secret{
				Data: map[string]interface{}{
					"period": "14400", // string instead of json.Number
				},
			},
			expected: false,
		},
		{
			name: "Period field with invalid json.Number",
			secret: &api.Secret{
				Data: map[string]interface{}{
					"period": json.Number("invalid"),
				},
			},
			expected: false,
		},
		{
			name: "Negative period (malicious Vault response) - P2 Issue #23",
			secret: &api.Secret{
				Data: map[string]interface{}{
					"period": json.Number("-1"),
				},
			},
			expected: false,
		},
		{
			name: "Period overflow (Int64 conversion error) - P2 Issue #23",
			secret: &api.Secret{
				Data: map[string]interface{}{
					"period": json.Number("99999999999999999999"), // Overflows int64
				},
			},
			expected: false,
		},
	}

	// Create test RuntimeContext
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// P1 Issue #32 Fix: isPeriodicToken() now returns (bool, int64) tuple
			result, periodSeconds := isPeriodicToken(rc, tt.secret)
			assert.Equal(t, tt.expected, result,
				"isPeriodicToken() returned %v, expected %v", result, tt.expected)

			// If periodic, verify period value is positive
			if result {
				assert.Greater(t, periodSeconds, int64(0),
					"Periodic token should have positive period, got %d", periodSeconds)
			} else {
				// Non-periodic tokens can have period <= 0 (or missing/malformed)
				// We return the actual value for diagnostic purposes, not sanitized to 0
				assert.LessOrEqual(t, periodSeconds, int64(0),
					"Non-periodic token should have period <= 0, got %d", periodSeconds)
			}
		})
	}
}

// TestIsPeriodicTokenConsistency verifies that isPeriodicToken() is deterministic
// (same input always produces same output). This is critical for race condition fix.
func TestIsPeriodicTokenConsistency(t *testing.T) {
	// Create test RuntimeContext
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	secret := &api.Secret{
		Data: map[string]interface{}{
			"period": json.Number("14400"),
		},
	}

	// Call function 10 times with same input
	// P1 Issue #32 Fix: isPeriodicToken() now returns (bool, int64) tuple
	results := make([]bool, 10)
	periodResults := make([]int64, 10)
	for i := 0; i < 10; i++ {
		results[i], periodResults[i] = isPeriodicToken(rc, secret)
	}

	// All results should be identical
	firstResult := results[0]
	firstPeriod := periodResults[0]
	for i, result := range results {
		assert.Equal(t, firstResult, result,
			"Call %d returned isPeriodic=%v, but first call returned %v (function is non-deterministic!)",
			i, result, firstResult)
		assert.Equal(t, firstPeriod, periodResults[i],
			"Call %d returned period=%d, but first call returned %d (function is non-deterministic!)",
			i, periodResults[i], firstPeriod)
	}

	assert.True(t, firstResult, "Secret with period=14400 should be periodic")
	assert.Equal(t, int64(14400), firstPeriod, "Secret should have period=14400")
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
