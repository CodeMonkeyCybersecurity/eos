package security_permissions

import (
	"os"
	"reflect"
	"strings"
	"testing"
)

// TestDefaultSecurityConfig tests the default configuration
func TestDefaultSecurityConfig(t *testing.T) {
	config := DefaultSecurityConfig()

	if config == nil {
		t.Fatal("DefaultSecurityConfig returned nil")
	}

	// Check default values
	if config.SSHDirectory == "" {
		t.Error("SSHDirectory should not be empty")
	}

	if config.IncludeSystem {
		t.Error("IncludeSystem should be false by default")
	}

	if !config.CreateBackups {
		t.Error("CreateBackups should be true by default")
	}

	if config.DryRun {
		t.Error("DryRun should be false by default")
	}

	if !config.VerifyOwnership {
		t.Error("VerifyOwnership should be true by default")
	}

	// Check default exclude patterns
	expectedPatterns := []string{"*.bak", "*.backup", ".git"}
	if !reflect.DeepEqual(config.ExcludePatterns, expectedPatterns) {
		t.Errorf("ExcludePatterns = %v, want %v", config.ExcludePatterns, expectedPatterns)
	}

	// SSH directory should contain $HOME
	if !strings.Contains(config.SSHDirectory, "$HOME") && !strings.Contains(config.SSHDirectory, os.Getenv("HOME")) {
		t.Error("SSHDirectory should reference home directory")
	}
}

// TestGetPermissionRules tests retrieval of permission rules
func TestGetPermissionRules(t *testing.T) {
	tests := []struct {
		name       string
		categories []string
		wantCount  int
		wantRules  bool
	}{
		{
			name:       "ssh category only",
			categories: []string{"ssh"},
			wantCount:  len(SSHPermissionRules),
			wantRules:  true,
		},
		{
			name:       "system category only",
			categories: []string{"system"},
			wantCount:  len(SystemPermissionRules),
			wantRules:  true,
		},
		{
			name:       "ssl category only",
			categories: []string{"ssl"},
			wantCount:  len(SSLPermissionRules),
			wantRules:  true,
		},
		{
			name:       "multiple categories",
			categories: []string{"ssh", "system"},
			wantCount:  len(SSHPermissionRules) + len(SystemPermissionRules),
			wantRules:  true,
		},
		{
			name:       "unknown category",
			categories: []string{"unknown"},
			wantCount:  0,
			wantRules:  false,
		},
		{
			name:       "empty categories",
			categories: []string{},
			wantCount:  0,
			wantRules:  false,
		},
		{
			name:       "duplicate categories",
			categories: []string{"ssh", "ssh"},
			wantCount:  len(SSHPermissionRules) * 2, // Duplicates are included
			wantRules:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rules := GetPermissionRules(tt.categories)

			if len(rules) != tt.wantCount {
				t.Errorf("GetPermissionRules() returned %d rules, want %d", len(rules), tt.wantCount)
			}

			if tt.wantRules && len(rules) == 0 {
				t.Error("Expected rules but got none")
			}

			// Verify all rules have the correct category
			for _, rule := range rules {
				found := false
				for _, cat := range tt.categories {
					if rule.Category == cat {
						found = true
						break
					}
				}
				if tt.wantRules && !found {
					t.Errorf("Rule with category %q not in requested categories %v", rule.Category, tt.categories)
				}
			}
		})
	}
}

// TestIsPrivateKey tests private key detection
func TestIsPrivateKey(t *testing.T) {
	tests := []struct {
		filename string
		want     bool
	}{
		// Private keys
		{"id_rsa", true},
		{"id_dsa", true},
		{"id_ecdsa", true},
		{"id_ed25519", true},
		{"private_key.pem", true},
		{"server.key", true},
		{"client_private.pem", true},
		{"my_private_key", true},

		// Public keys
		{"id_rsa.pub", false},
		{"id_dsa.pub", false},
		{"id_ecdsa.pub", false},
		{"id_ed25519.pub", false},
		{"public.key.pub", false},

		// Other files
		{"authorized_keys", false},
		{"known_hosts", false},
		{"config", false},
		{"", false},
		{"readme.txt", false},

		// Edge cases
		{"private.pub", false},       // .pub extension takes precedence
		{"id_rsa.pub.backup", false}, // Still ends with .pub
		{"keyprivate", true},         // Contains "key" and "private"
		{"id_rsa_backup", true},      // Contains id_rsa
		{"test_id_rsa_test", true},   // Contains id_rsa
		{"PRIVATE", true},            // Case insensitive
	}

	for _, tt := range tests {
		t.Run(tt.filename, func(t *testing.T) {
			got := IsPrivateKey(tt.filename)
			if got != tt.want {
				t.Errorf("IsPrivateKey(%q) = %v, want %v", tt.filename, got, tt.want)
			}
		})
	}
}

// TestPermissionRuleStructure tests the PermissionRule structure
func TestPermissionRuleStructure(t *testing.T) {
	rule := PermissionRule{
		Path:        "/test/path",
		Mode:        0600,
		Description: "Test file",
		Required:    true,
		Category:    "test",
	}

	if rule.Path != "/test/path" {
		t.Errorf("Path = %q, want %q", rule.Path, "/test/path")
	}

	if rule.Mode != 0600 {
		t.Errorf("Mode = %o, want %o", rule.Mode, 0600)
	}

	if !rule.Required {
		t.Error("Required should be true")
	}
}

// TestPermissionCheckStructure tests the PermissionCheck structure
func TestPermissionCheckStructure(t *testing.T) {
	check := PermissionCheck{
		Rule: PermissionRule{
			Path: "/test",
			Mode: 0600,
		},
		Exists:       true,
		CurrentMode:  0644,
		ExpectedMode: 0600,
		NeedsChange:  true,
		Error:        "",
	}

	if !check.NeedsChange {
		t.Error("NeedsChange should be true when modes differ")
	}

	if check.CurrentMode == check.ExpectedMode {
		t.Error("Current and expected modes should differ in this test")
	}
}

// TestSSHPermissionRules tests SSH permission rules configuration
func TestSSHPermissionRules(t *testing.T) {
	// Verify SSH rules are properly configured
	requiredPaths := map[string]os.FileMode{
		"$HOME/.ssh":                 0700,
		"$HOME/.ssh/id_rsa":          0600,
		"$HOME/.ssh/id_ed25519":      0600,
		"$HOME/.ssh/config":          0600,
		"$HOME/.ssh/authorized_keys": 0600,
		"$HOME/.ssh/known_hosts":     0644,
	}

	for _, rule := range SSHPermissionRules {
		expectedMode, exists := requiredPaths[rule.Path]
		if !exists {
			t.Errorf("Unexpected SSH rule path: %s", rule.Path)
			continue
		}

		if rule.Mode != expectedMode {
			t.Errorf("SSH rule %s has mode %o, want %o", rule.Path, rule.Mode, expectedMode)
		}

		if rule.Category != "ssh" {
			t.Errorf("SSH rule %s has category %q, want 'ssh'", rule.Path, rule.Category)
		}

		// Only SSH directory itself should be required
		if rule.Path == "$HOME/.ssh" && !rule.Required {
			t.Error("SSH directory should be required")
		} else if rule.Path != "$HOME/.ssh" && rule.Required {
			t.Errorf("SSH file %s should not be required", rule.Path)
		}
	}
}

// TestSystemPermissionRules tests system permission rules configuration
func TestSystemPermissionRules(t *testing.T) {
	// Critical system files that should have specific permissions
	criticalFiles := map[string]struct {
		mode     os.FileMode
		required bool
	}{
		"/etc/passwd":  {0644, true},
		"/etc/shadow":  {0640, true},
		"/etc/group":   {0644, true},
		"/etc/gshadow": {0640, false},
		"/etc/sudoers": {0440, false},
		"/tmp":         {01777, true}, // Sticky bit
		"/root":        {0700, true},
	}

	for _, rule := range SystemPermissionRules {
		critical, exists := criticalFiles[rule.Path]
		if !exists {
			// Additional system files are okay
			continue
		}

		if rule.Mode != critical.mode {
			t.Errorf("System rule %s has mode %o, want %o", rule.Path, rule.Mode, critical.mode)
		}

		if rule.Required != critical.required {
			t.Errorf("System rule %s required = %v, want %v", rule.Path, rule.Required, critical.required)
		}

		if rule.Category != "system" {
			t.Errorf("System rule %s has category %q, want 'system'", rule.Path, rule.Category)
		}
	}
}

// TestSSLPermissionRules tests SSL permission rules configuration
func TestSSLPermissionRules(t *testing.T) {
	expectedRules := map[string]os.FileMode{
		"/etc/ssl/private": 0700,
		"/etc/ssl/certs":   0755,
	}

	for _, rule := range SSLPermissionRules {
		expectedMode, exists := expectedRules[rule.Path]
		if !exists {
			t.Errorf("Unexpected SSL rule path: %s", rule.Path)
			continue
		}

		if rule.Mode != expectedMode {
			t.Errorf("SSL rule %s has mode %o, want %o", rule.Path, rule.Mode, expectedMode)
		}

		if rule.Category != "ssl" {
			t.Errorf("SSL rule %s has category %q, want 'ssl'", rule.Path, rule.Category)
		}

		if rule.Required {
			t.Errorf("SSL rule %s should not be required", rule.Path)
		}
	}
}

// TestPermissionSummaryCalculation tests summary calculation logic
func TestPermissionSummaryCalculation(t *testing.T) {
	summary := PermissionSummary{
		TotalFiles:   10,
		FilesFixed:   3,
		FilesSkipped: 5,
		Errors:       []string{"error1", "error2"},
		Success:      false,
	}

	// Files accounted for should equal total
	accounted := summary.FilesFixed + summary.FilesSkipped + len(summary.Errors)
	if accounted != summary.TotalFiles {
		t.Errorf("Files accounted for (%d) != TotalFiles (%d)", accounted, summary.TotalFiles)
	}

	// Success should be false when there are errors
	if summary.Success && len(summary.Errors) > 0 {
		t.Error("Success should be false when errors exist")
	}
}

// TestSpecialPermissionBits tests handling of special permission bits
func TestSpecialPermissionBits(t *testing.T) {
	// Test that special bits are preserved
	specialModes := []os.FileMode{
		01777, // Sticky bit (for /tmp)
		02755, // Setgid
		04755, // Setuid
		06755, // Setuid + Setgid
		07777, // All special bits
	}

	for _, mode := range specialModes {
		// Ensure mode is valid
		if mode > 07777 {
			t.Errorf("Invalid mode: %o", mode)
		}

		// Test with a rule
		rule := PermissionRule{
			Path:     "/test",
			Mode:     mode,
			Category: "test",
		}

		// Mode should be preserved
		if rule.Mode != mode {
			t.Errorf("Mode not preserved: got %o, want %o", rule.Mode, mode)
		}
	}
}

// TestEmptyStructInitialization tests zero-value struct behavior
func TestEmptyStructInitialization(t *testing.T) {
	// Test empty PermissionRule
	var rule PermissionRule
	if rule.Path != "" || rule.Mode != 0 || rule.Required {
		t.Error("Empty PermissionRule should have zero values")
	}

	// Test empty PermissionCheck
	var check PermissionCheck
	if check.Exists || check.NeedsChange || check.Error != "" {
		t.Error("Empty PermissionCheck should have zero values")
	}

	// Test empty SecurityConfig
	var config SecurityConfig
	if config.CreateBackups || config.DryRun || config.VerifyOwnership {
		t.Error("Empty SecurityConfig should have false booleans")
	}
}
