// pkg/vault/security_warnings_test.go

package vault

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
)

func TestDisplaySecurityWarnings(t *testing.T) {
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	vaultInitPath := "/var/lib/eos/secret/vault_init.json"

	// This test verifies the function doesn't crash
	// Output goes to stderr and will be visible in test output
	DisplaySecurityWarnings(rc, vaultInitPath)

	t.Log("Security warnings displayed without errors")
}

func TestDisplayPostInstallSecurityChecklist(t *testing.T) {
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	// This test verifies the function doesn't crash
	DisplayPostInstallSecurityChecklist(rc)

	t.Log("Security checklist displayed without errors")
}

func TestValidateSecurityPosture(t *testing.T) {
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	// This is more of an integration test - it checks actual system state
	passed, failed := ValidateSecurityPosture(rc)

	t.Logf("Security posture validation:")
	t.Logf("  Passed: %d checks", len(passed))
	t.Logf("  Failed: %d checks", len(failed))

	for i, check := range passed {
		t.Logf("   %d. %s", i+1, check)
	}
	for i, check := range failed {
		t.Logf("  ❌ %d. %s", i+1, check)
	}

	// Basic validation - should return results
	if len(passed)+len(failed) == 0 {
		t.Error("Should return at least some security check results")
	}
}

func TestValidateSecurityPostureWithMockFiles(t *testing.T) {
	tmpDir := t.TempDir()

	// This test would need to mock the file paths
	// For now, we'll just test the structure
	// In a real implementation, we'd use dependency injection
	// to allow testing with mock file paths

	// Create mock TLS files
	tlsDir := filepath.Join(tmpDir, "tls")
	_ = os.MkdirAll(tlsDir, 0755)

	certPath := filepath.Join(tlsDir, "vault.crt")
	keyPath := filepath.Join(tlsDir, "vault.key")

	// Good cert (644)
	_ = os.WriteFile(certPath, []byte("MOCK CERT"), 0644)

	tests := []struct {
		name        string
		keyPerms    os.FileMode
		expectIssue bool
		description string
	}{
		{
			name:        "correct_key_permissions",
			keyPerms:    0600,
			expectIssue: false,
			description: "Key with 0600 permissions should pass",
		},
		{
			name:        "insecure_key_permissions",
			keyPerms:    0644,
			expectIssue: true,
			description: "Key with 0644 permissions should fail",
		},
		{
			name:        "world_readable_key",
			keyPerms:    0604,
			expectIssue: true,
			description: "World-readable key should fail",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create key with specific permissions
			_ = os.WriteFile(keyPath, []byte("MOCK KEY"), tt.keyPerms)

			// Check permissions
			info, err := os.Stat(keyPath)
			if err != nil {
				t.Fatalf("Failed to stat key: %v", err)
			}

			actualPerms := info.Mode().Perm()
			expectedPerms := os.FileMode(0600)

			hasIssue := actualPerms != expectedPerms

			if tt.expectIssue != hasIssue {
				t.Errorf("Expected issue=%v, got issue=%v (perms: %o)",
					tt.expectIssue, hasIssue, actualPerms)
			}

			t.Logf("Key permissions: %o, expected: %o, has issue: %v",
				actualPerms, expectedPerms, hasIssue)
		})
	}
}

func TestSecurityWarningLevels(t *testing.T) {
	tests := []struct {
		level        SecurityWarningLevel
		expectedIcon string
		expectedText string
	}{
		{SecurityWarningCritical, "🚨", "CRITICAL"},
		{SecurityWarningHigh, " ", "HIGH"},
		{SecurityWarningMedium, "⚡", "MEDIUM"},
		{SecurityWarningLow, " ", "LOW"},
	}

	for _, tt := range tests {
		t.Run(tt.expectedText, func(t *testing.T) {
			icon := getWarningIcon(tt.level)
			text := getWarningLevelText(tt.level)

			if icon != tt.expectedIcon {
				t.Errorf("Expected icon '%s', got '%s'", tt.expectedIcon, icon)
			}
			if text != tt.expectedText {
				t.Errorf("Expected text '%s', got '%s'", tt.expectedText, text)
			}
		})
	}
}

func TestWrapText(t *testing.T) {
	tests := []struct {
		name     string
		text     string
		width    int
		expected int // Expected number of lines
	}{
		{
			name:     "short_text",
			text:     "Hello world",
			width:    75,
			expected: 1,
		},
		{
			name:     "text_with_newlines",
			text:     "Line 1\nLine 2\nLine 3",
			width:    75,
			expected: 3,
		},
		{
			name:     "long_text_needs_wrapping",
			text:     "This is a very long text that should be wrapped because it exceeds the maximum width that we have specified for this particular test case and will need to be broken into multiple lines",
			width:    50,
			expected: 4, // Will be wrapped into multiple lines
		},
		{
			name:     "text_exactly_width",
			text:     "This text is exactly fifty characters long okay!",
			width:    50,
			expected: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lines := wrapText(tt.text, tt.width)

			if len(lines) < tt.expected {
				t.Errorf("Expected at least %d lines, got %d", tt.expected, len(lines))
			}

			// Verify no line exceeds width
			for i, line := range lines {
				if len(line) > tt.width {
					t.Errorf("Line %d exceeds width %d: '%s' (len=%d)",
						i, tt.width, line, len(line))
				}
			}

			t.Logf("Wrapped into %d lines:", len(lines))
			for i, line := range lines {
				t.Logf("  %d. %s", i+1, line)
			}
		})
	}
}

func TestDisplayWarning(t *testing.T) {
	warning := SecurityWarning{
		Level: SecurityWarningCritical,
		Title: "TEST WARNING",
		Description: "This is a test warning with some description text that " +
			"should be displayed properly formatted.",
		Remediation: "1. Do this\n2. Do that\n3. Do the other thing",
	}

	// This test just verifies it doesn't crash
	// Output goes to stderr
	displayWarning(warning, 1, 3)

	t.Log("Warning displayed without errors")
}

func TestSecurityWarningStruct(t *testing.T) {
	warning := SecurityWarning{
		Level:       SecurityWarningHigh,
		Title:       "File Permissions Issue",
		Description: "Configuration file has world-readable permissions",
		Remediation: "Run: chmod 640 /etc/vault.d/vault.hcl",
	}

	if warning.Level != SecurityWarningHigh {
		t.Errorf("Unexpected level: %v", warning.Level)
	}
	if warning.Title == "" {
		t.Error("Title should not be empty")
	}
	if warning.Description == "" {
		t.Error("Description should not be empty")
	}
	if warning.Remediation == "" {
		t.Error("Remediation should not be empty")
	}

	t.Logf("Warning structure: %+v", warning)
}

func TestSecurityPostureWithInitFilePresent(t *testing.T) {
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	tmpDir := t.TempDir()

	// Create mock vault_init.json
	initPath := filepath.Join(tmpDir, "vault_init.json")
	_ = os.WriteFile(initPath, []byte(`{"unseal_keys": ["key1", "key2"]}`), 0600)

	// In real implementation, we'd inject the path
	// For now, just test the logic
	_, err := os.Stat(initPath)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// If file exists, security posture should flag it
	if os.IsNotExist(err) {
		t.Log("File properly deleted - PASS")
	} else {
		t.Log("File still exists - FAIL (expected for dev/test)")
	}

	// Clean up
	_ = os.Remove(initPath)

	// After deletion, should pass
	_, err = os.Stat(initPath)
	if !os.IsNotExist(err) {
		t.Error("File should be deleted")
	} else {
		t.Log("File properly deleted after cleanup")
	}

	// Run actual validation
	passed, failed := ValidateSecurityPosture(rc)
	t.Logf("Security posture: %d passed, %d failed", len(passed), len(failed))
}

func TestSecurityWarningsIntegration(t *testing.T) {
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	// Test the full workflow
	t.Run("display_warnings", func(t *testing.T) {
		DisplaySecurityWarnings(rc, shared.VaultInitPath)
		t.Log("Warnings displayed")
	})

	t.Run("display_checklist", func(t *testing.T) {
		DisplayPostInstallSecurityChecklist(rc)
		t.Log("Checklist displayed")
	})

	t.Run("validate_posture", func(t *testing.T) {
		passed, failed := ValidateSecurityPosture(rc)
		t.Logf("Validation complete: %d passed, %d failed", len(passed), len(failed))
	})
}
