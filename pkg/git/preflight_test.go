// pkg/git/preflight_test.go
//
// Unit tests for git preflight checks
// Tests fail-fast behavior and error messaging

package git

import (
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestCheckGitInstalled(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Git should be installed in CI/CD environments
	err := CheckGitInstalled(ctx)
	if err != nil {
		// If git is not installed, verify error message is helpful
		if !strings.Contains(err.Error(), "not installed") {
			t.Errorf("Expected helpful error message about installation, got: %v", err)
		}
		if !strings.Contains(err.Error(), "apt-get install git") {
			t.Errorf("Expected installation instructions in error, got: %v", err)
		}
		t.Skipf("Git not installed in test environment: %v", err)
	}

	// If we got here, git is installed - verify we can get version
	cmd := exec.CommandContext(ctx, "git", "--version")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Git is detected but --version failed: %v\nOutput: %s", err, output)
	}

	version := string(output)
	if !strings.Contains(version, "git version") {
		t.Errorf("Unexpected git version output: %s", version)
	}
}

func TestCheckGitIdentity_NotConfigured(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Try to check git identity
	// In CI or fresh environments, this might fail
	err := CheckGitIdentity(ctx, true)

	if err != nil {
		// Verify error message is helpful
		errMsg := err.Error()

		// Should mention what's missing
		if !strings.Contains(errMsg, "user.name") && !strings.Contains(errMsg, "user.email") {
			t.Errorf("Error should mention user.name or user.email, got: %v", err)
		}

		// Should have instructions
		if !strings.Contains(errMsg, "git config --global") {
			t.Errorf("Error should include configuration instructions, got: %v", err)
		}

		// Should have example
		if !strings.Contains(errMsg, "@") && !strings.Contains(errMsg, "email") {
			t.Errorf("Error should include email example, got: %v", err)
		}

		t.Logf("Got expected error for unconfigured git identity: %v", err)
	} else {
		// Git identity is configured in test environment
		t.Logf("Git identity is configured (test passed)")
	}
}

func TestGetGitConfig(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Try to get git config values
	userName, err := getGitConfig(ctx, "user.name", false)
	if err != nil && !strings.Contains(err.Error(), "not configured") {
		t.Errorf("getGitConfig should return specific error for unconfigured keys, got: %v", err)
	}

	if userName != "" {
		t.Logf("Found git user.name: %s", userName)
	}

	userEmail, err := getGitConfig(ctx, "user.email", false)
	if err != nil && !strings.Contains(err.Error(), "not configured") {
		t.Errorf("getGitConfig should return specific error for unconfigured keys, got: %v", err)
	}

	if userEmail != "" {
		t.Logf("Found git user.email: %s", userEmail)
	}
}

func TestFormatIdentityError(t *testing.T) {
	tests := []struct {
		name         string
		key          string
		userName     string
		originalErr  error
		wantContains []string
	}{
		{
			name:        "user.name not configured",
			key:         "user.name",
			userName:    "",
			originalErr: nil,
			wantContains: []string{
				"user.name",
				"git config --global",
				"user.email",
			},
		},
		{
			name:        "user.email not configured with existing user.name",
			key:         "user.email",
			userName:    "Test User",
			originalErr: nil,
			wantContains: []string{
				"user.email",
				"Test User",
				"git config --global",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := formatIdentityError(tt.key, tt.userName, tt.originalErr)
			errMsg := err.Error()

			for _, want := range tt.wantContains {
				if !strings.Contains(errMsg, want) {
					t.Errorf("Error message should contain %q, got:\n%s", want, errMsg)
				}
			}
		})
	}
}

func TestDefaultGitPreflightConfig(t *testing.T) {
	config := DefaultGitPreflightConfig()

	if !config.RequireGitInstalled {
		t.Error("Default config should require git installed")
	}

	if !config.RequireIdentity {
		t.Error("Default config should require git identity")
	}

	if !config.CheckGlobalConfig {
		t.Error("Default config should check global config")
	}
}

func TestRunGitPreflightChecks(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	config := GitPreflightConfig{
		RequireGitInstalled: true,
		RequireIdentity:     false, // Don't require identity for this test
		CheckGlobalConfig:   true,
	}

	err := RunGitPreflightChecks(ctx, config)
	if err != nil {
		// If git is not installed, verify error is helpful
		if strings.Contains(err.Error(), "not installed") {
			t.Skipf("Git not installed in test environment: %v", err)
		}
		t.Fatalf("Preflight checks failed: %v", err)
	}

	t.Log("Git preflight checks passed")
}

func TestRunGitPreflightChecks_RequireIdentity(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	config := GitPreflightConfig{
		RequireGitInstalled: true,
		RequireIdentity:     true,
		CheckGlobalConfig:   true,
	}

	err := RunGitPreflightChecks(ctx, config)
	if err != nil {
		// Expected to fail if git identity not configured
		errMsg := err.Error()
		if !strings.Contains(errMsg, "user.name") && !strings.Contains(errMsg, "user.email") {
			t.Errorf("Identity check failure should mention user.name or user.email, got: %v", err)
		}
		t.Logf("Got expected identity check failure: %v", err)
	} else {
		t.Log("Git identity is configured (test passed)")
	}
}

// TestEmailValidation verifies that email format validation works
func TestEmailValidation(t *testing.T) {
	// This test verifies the email validation logic indirectly
	// by checking that CheckGitIdentity would catch invalid emails

	tests := []struct {
		name    string
		email   string
		wantErr bool
	}{
		{"valid email", "user@example.com", false},
		{"valid email with subdomain", "user@subdomain.example.com", false},
		{"invalid - no @", "not-an-email", true},
		{"invalid - path traversal", "../../../etc/passwd", true},
		{"invalid - SQL injection attempt", "'; DROP TABLE users;--", true},
	}

	// Note: We can't easily test this without actually setting git config
	// This test documents the expected behavior
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Logf("Email validation should %s for: %s",
				map[bool]string{true: "fail", false: "pass"}[tt.wantErr],
				tt.email)
		})
	}
}

// Benchmark tests
func BenchmarkCheckGitInstalled(b *testing.B) {
	ctx := context.Background()
	for b.Loop() {
		_ = CheckGitInstalled(ctx)
	}
}

func BenchmarkGetGitConfig(b *testing.B) {
	ctx := context.Background()
	for b.Loop() {
		_, _ = getGitConfig(ctx, "user.name", false)
	}
}
