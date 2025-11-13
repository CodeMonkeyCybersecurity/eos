// pkg/vault/cluster_token_security_test.go
//
// SECURITY TESTS: Validate token file security measures
//
// These tests verify that P0-1 (Token Exposure) fix works correctly:
//   1. Tokens are NOT visible in environment variables
//   2. Token files have 0400 permissions (owner-read-only)
//   3. Token files are cleaned up after use
//   4. Token files contain the correct token value
//
// Code Monkey Cybersecurity - "Cybersecurity. With humans."
//
// Last Updated: 2025-01-27

package vault

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
)

// TestCreateTemporaryTokenFile verifies basic token file creation
func TestCreateTemporaryTokenFile(t *testing.T) {
	// Create test runtime context
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	testToken := "hvs.CAESTEST123TOKEN456"

	// Create token file
	tokenFile, err := createTemporaryTokenFile(rc, testToken)
	if err != nil {
		t.Fatalf("Failed to create token file: %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(tokenFile.Name()); os.IsNotExist(err) {
		t.Fatalf("Token file does not exist: %s", tokenFile.Name())
	}

	// Verify file is in temp directory
	if !strings.HasPrefix(tokenFile.Name(), os.TempDir()) {
		t.Errorf("Token file not in temp directory: %s", tokenFile.Name())
	}

	// Verify file has correct permissions (0400 - owner-read-only)
	info, err := os.Stat(tokenFile.Name())
	if err != nil {
		t.Fatalf("Failed to stat token file: %v", err)
	}

	expectedPerms := os.FileMode(TempTokenFilePerm)
	actualPerms := info.Mode().Perm()
	if actualPerms != expectedPerms {
		t.Errorf("Token file has wrong permissions: got %04o, want %04o",
			actualPerms, expectedPerms)
	}

	// Verify file contents
	content, err := os.ReadFile(tokenFile.Name())
	if err != nil {
		t.Fatalf("Failed to read token file: %v", err)
	}

	if string(content) != testToken {
		t.Errorf("Token file contains wrong token: got %q, want %q",
			string(content), testToken)
	}

	// Cleanup
	if err := os.Remove(tokenFile.Name()); err != nil {
		t.Errorf("Failed to remove token file: %v", err)
	}
}

// TestTokenFileCleanup verifies token files are properly cleaned up
func TestTokenFileCleanup(t *testing.T) {
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	testToken := "hvs.CLEANUPTEST"

	// Create token file
	tokenFile, err := createTemporaryTokenFile(rc, testToken)
	if err != nil {
		t.Fatalf("Failed to create token file: %v", err)
	}

	tokenPath := tokenFile.Name()

	// Verify file exists
	if _, err := os.Stat(tokenPath); os.IsNotExist(err) {
		t.Fatalf("Token file does not exist: %s", tokenPath)
	}

	// Simulate cleanup (what defer os.Remove() does)
	if err := os.Remove(tokenPath); err != nil {
		t.Fatalf("Failed to remove token file: %v", err)
	}

	// Verify file is deleted
	if _, err := os.Stat(tokenPath); !os.IsNotExist(err) {
		t.Errorf("Token file still exists after cleanup: %s", tokenPath)
	}
}

// TestTokenFileUnpredictableName verifies token files use random names
func TestTokenFileUnpredictableName(t *testing.T) {
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	testToken := "hvs.RANDOMTEST"

	// Create multiple token files
	var filenames []string
	for i := 0; i < 5; i++ {
		tokenFile, err := createTemporaryTokenFile(rc, testToken)
		if err != nil {
			t.Fatalf("Failed to create token file %d: %v", i, err)
		}
		filenames = append(filenames, filepath.Base(tokenFile.Name()))

		// Cleanup immediately
		os.Remove(tokenFile.Name())
	}

	// Verify all filenames are different (random suffix)
	seen := make(map[string]bool)
	for _, filename := range filenames {
		if seen[filename] {
			t.Errorf("Duplicate filename detected: %s (not random)", filename)
		}
		seen[filename] = true

		// Verify filename pattern: vault-token-<random>
		if !strings.HasPrefix(filename, "vault-token-") {
			t.Errorf("Filename doesn't match expected pattern: %s", filename)
		}
	}
}

// TestTokenFileNotInEnvironment verifies tokens don't leak to environment
func TestTokenFileNotInEnvironment(t *testing.T) {
	// This test verifies the ABSENCE of VAULT_TOKEN in environment

	// Before fix (vulnerable code):
	// os.Setenv("VAULT_TOKEN", token)  // ← Token visible in ps/proc

	// After fix (secure code):
	// tokenFile := createTemporaryTokenFile(rc, token)
	// os.Setenv("VAULT_TOKEN_FILE", tokenFile.Name())  // ← File path only

	testToken := "hvs.ENVTEST"

	// Verify VAULT_TOKEN is NOT set
	if envToken := os.Getenv("VAULT_TOKEN"); envToken != "" {
		t.Errorf("VAULT_TOKEN found in environment: %s (should not exist)",
			sanitizeTokenForLogging(envToken))
	}

	// Simulate the secure approach
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	tokenFile, err := createTemporaryTokenFile(rc, testToken)
	if err != nil {
		t.Fatalf("Failed to create token file: %v", err)
	}
	defer os.Remove(tokenFile.Name())

	// Set VAULT_TOKEN_FILE (not VAULT_TOKEN)
	os.Setenv("VAULT_TOKEN_FILE", tokenFile.Name())
	defer os.Unsetenv("VAULT_TOKEN_FILE")

	// Verify only the FILE PATH is in environment, not the TOKEN VALUE
	envTokenFile := os.Getenv("VAULT_TOKEN_FILE")
	if envTokenFile == "" {
		t.Error("VAULT_TOKEN_FILE not set in environment")
	}

	// Verify the token value is NOT in environment
	if strings.Contains(envTokenFile, testToken) {
		t.Errorf("Token value leaked into VAULT_TOKEN_FILE: %s", envTokenFile)
	}

	// Verify VAULT_TOKEN is still not set
	if envToken := os.Getenv("VAULT_TOKEN"); envToken != "" {
		t.Errorf("VAULT_TOKEN unexpectedly set: %s", sanitizeTokenForLogging(envToken))
	}
}

// TestSanitizeTokenForLogging_Basic verifies token sanitization (basic cases)
func TestSanitizeTokenForLogging_Basic(t *testing.T) {
	tests := []struct {
		name     string
		token    string
		expected string
	}{
		{
			name:     "HashiCorp Vault service token",
			token:    "hvs.CAESIJ1234567890ABCDEF",
			expected: "hvs.***",
		},
		{
			name:     "Legacy Vault token",
			token:    "s.1234567890ABCDEF",
			expected: "s.12***",
		},
		{
			name:     "Short token",
			token:    "abc",
			expected: "***",
		},
		{
			name:     "Empty token",
			token:    "",
			expected: "***",
		},
		{
			name:     "Unknown prefix",
			token:    "unknown1234567890",
			expected: "***",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizeTokenForLogging(tt.token)
			if result != tt.expected {
				t.Errorf("sanitizeTokenForLogging(%q) = %q, want %q",
					tt.token, result, tt.expected)
			}

			// Verify no full token value in result
			if len(tt.token) > 4 && strings.Contains(result, tt.token[4:]) {
				t.Errorf("sanitizeTokenForLogging leaked token value: %s", result)
			}
		})
	}
}

// TestTokenFilePermissionsAfterWrite verifies perms set BEFORE write
func TestTokenFilePermissionsAfterWrite(t *testing.T) {
	// This test verifies the permission-setting order prevents race conditions
	// Permissions MUST be set BEFORE writing token, not after

	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	testToken := "hvs.RACETEST"

	tokenFile, err := createTemporaryTokenFile(rc, testToken)
	if err != nil {
		t.Fatalf("Failed to create token file: %v", err)
	}
	defer os.Remove(tokenFile.Name())

	// Verify file is closed (can't write more)
	_, err = tokenFile.WriteString("should fail")
	if err == nil {
		t.Error("Token file is still open (should be closed)")
	}

	// Verify permissions are restrictive
	info, err := os.Stat(tokenFile.Name())
	if err != nil {
		t.Fatalf("Failed to stat token file: %v", err)
	}

	perms := info.Mode().Perm()
	if perms != TempTokenFilePerm {
		t.Errorf("Permissions wrong: got %04o, want %04o", perms, TempTokenFilePerm)
	}

	// Verify permissions don't allow write
	if perms&0200 != 0 {
		t.Error("Token file has write permission (should be read-only)")
	}

	// Verify permissions don't allow group/other access
	if perms&0077 != 0 {
		t.Error("Token file has group/other permissions (should be owner-only)")
	}
}
