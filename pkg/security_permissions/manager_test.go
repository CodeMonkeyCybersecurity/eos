package security_permissions

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestNewPermissionManager tests the creation of permission manager
func TestNewPermissionManager(t *testing.T) {
	tests := []struct {
		name   string
		config *SecurityConfig
		verify func(*testing.T, *PermissionManager)
	}{
		{
			name:   "with nil config uses defaults",
			config: nil,
			verify: func(t *testing.T, pm *PermissionManager) {
				if pm.config == nil {
					t.Error("Expected default config, got nil")
				}
				if !pm.config.CreateBackups {
					t.Error("Expected CreateBackups to be true by default")
				}
			},
		},
		{
			name: "with custom config",
			config: &SecurityConfig{
				DryRun:        true,
				CreateBackups: false,
				SSHDirectory:  "/custom/ssh",
			},
			verify: func(t *testing.T, pm *PermissionManager) {
				if !pm.config.DryRun {
					t.Error("Expected DryRun to be true")
				}
				if pm.config.CreateBackups {
					t.Error("Expected CreateBackups to be false")
				}
				if pm.config.SSHDirectory != "/custom/ssh" {
					t.Errorf("Expected SSHDirectory to be /custom/ssh, got %s", pm.config.SSHDirectory)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pm := NewPermissionManager(tt.config)
			tt.verify(t, pm)
		})
	}
}

// TestCheckSinglePath tests permission checking for single paths
func TestCheckSinglePath(t *testing.T) {
	tempDir := t.TempDir()

	// Create test files with different permissions
	testFile := filepath.Join(tempDir, "test.txt")
	if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
		t.Fatal(err)
	}

	privateFile := filepath.Join(tempDir, "private.key")
	if err := os.WriteFile(privateFile, []byte("key"), 0600); err != nil {
		t.Fatal(err)
	}

	pm := NewPermissionManager(nil)

	tests := []struct {
		name            string
		path            string
		expectedMode    os.FileMode
		description     string
		required        bool
		wantExists      bool
		wantNeedsChange bool
		wantError       string
	}{
		{
			name:            "existing file with correct permissions",
			path:            privateFile,
			expectedMode:    0600,
			description:     "private key",
			required:        true,
			wantExists:      true,
			wantNeedsChange: false,
		},
		{
			name:            "existing file with incorrect permissions",
			path:            testFile,
			expectedMode:    0600,
			description:     "test file",
			required:        true,
			wantExists:      true,
			wantNeedsChange: true,
		},
		{
			name:         "non-existent required file",
			path:         filepath.Join(tempDir, "missing.txt"),
			expectedMode: 0600,
			description:  "missing file",
			required:     true,
			wantExists:   false,
			wantError:    "Required path does not exist",
		},
		{
			name:         "non-existent optional file",
			path:         filepath.Join(tempDir, "optional.txt"),
			expectedMode: 0600,
			description:  "optional file",
			required:     false,
			wantExists:   false,
			wantError:    "Path does not exist (optional)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			check := pm.checkSinglePath(tt.path, tt.expectedMode, tt.description, tt.required)

			if check.Exists != tt.wantExists {
				t.Errorf("Exists = %v, want %v", check.Exists, tt.wantExists)
			}

			if check.NeedsChange != tt.wantNeedsChange {
				t.Errorf("NeedsChange = %v, want %v", check.NeedsChange, tt.wantNeedsChange)
			}

			if tt.wantError != "" && check.Error != tt.wantError {
				t.Errorf("Error = %q, want %q", check.Error, tt.wantError)
			}
		})
	}
}

// TestFixSinglePath tests permission fixing for single paths
func TestFixSinglePath(t *testing.T) {
	tempDir := t.TempDir()

	// Create test file with wrong permissions
	testFile := filepath.Join(tempDir, "fix-test.txt")
	if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name         string
		dryRun       bool
		createBackup bool
		wantFixed    bool
	}{
		{
			name:         "dry run mode - no changes",
			dryRun:       true,
			createBackup: false,
			wantFixed:    false,
		},
		{
			name:         "actual fix without backup",
			dryRun:       false,
			createBackup: false,
			wantFixed:    true,
		},
		{
			name:         "actual fix with backup",
			dryRun:       false,
			createBackup: true,
			wantFixed:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset file permissions for each test
			os.Chmod(testFile, 0644)

			backupDir := filepath.Join(tempDir, "backups", tt.name)

			pm := NewPermissionManager(&SecurityConfig{
				DryRun:          tt.dryRun,
				CreateBackups:   tt.createBackup,
				BackupDirectory: backupDir,
			})

			check := pm.fixSinglePath(testFile, 0600, "test file", true)

			if check.Error != "" {
				t.Errorf("Unexpected error: %v", check.Error)
			}

			// Verify file permissions
			stat, err := os.Stat(testFile)
			if err != nil {
				t.Fatal(err)
			}

			currentMode := stat.Mode() & os.ModePerm
			if tt.wantFixed && currentMode != 0600 {
				t.Errorf("File permissions not fixed: got %o, want %o", currentMode, 0600)
			}

			if !tt.wantFixed && currentMode != 0644 {
				t.Errorf("File permissions changed in dry-run: got %o, want %o", currentMode, 0644)
			}

			// Check backup was created if requested
			if tt.createBackup && !tt.dryRun {
				entries, _ := os.ReadDir(backupDir)
				if len(entries) == 0 {
					t.Error("Expected backup file to be created")
				}
			}
		})
	}
}

// TestShouldExcludePath tests path exclusion logic
func TestShouldExcludePath(t *testing.T) {
	pm := NewPermissionManager(&SecurityConfig{
		ExcludePatterns: []string{"*.bak", "*.backup", ".git", "temp*"},
	})

	tests := []struct {
		path     string
		excluded bool
	}{
		{"/home/user/file.txt", false},
		{"/home/user/file.bak", true},
		{"/home/user/data.backup", true},
		{"/home/user/.git", true},
		{"/home/user/tempfile", true},
		{"/home/user/temporary", true},
		{"/home/user/mytemp", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			excluded := pm.shouldExcludePath(tt.path)
			if excluded != tt.excluded {
				t.Errorf("shouldExcludePath(%q) = %v, want %v", tt.path, excluded, tt.excluded)
			}
		})
	}
}

// TestScanSSHDirectory tests SSH directory scanning
func TestScanSSHDirectory(t *testing.T) {
	tempDir := t.TempDir()
	sshDir := filepath.Join(tempDir, ".ssh")

	// Create SSH directory structure with correct permissions
	os.Mkdir(sshDir, 0700)
	os.WriteFile(filepath.Join(sshDir, "id_rsa"), []byte("private"), 0600)
	os.WriteFile(filepath.Join(sshDir, "id_rsa.pub"), []byte("public"), 0644)
	os.WriteFile(filepath.Join(sshDir, "config"), []byte("config"), 0644)     // Wrong permission
	os.WriteFile(filepath.Join(sshDir, "known_hosts"), []byte("hosts"), 0644) // Correct permission

	pm := NewPermissionManager(nil)
	result, err := pm.ScanSSHDirectory(sshDir)

	if err != nil {
		t.Fatalf("ScanSSHDirectory failed: %v", err)
	}

	if result.Category != "ssh" {
		t.Errorf("Expected category 'ssh', got %q", result.Category)
	}

	if result.TotalChecks != 5 { // dir + 4 files
		t.Errorf("Expected 5 checks, got %d", result.TotalChecks)
	}

	// Debug: print all checks to see what's failing
	for _, check := range result.Checks {
		if check.NeedsChange {
			t.Logf("Failed check: %s (current: %o, expected: %o)", check.Rule.Path, check.CurrentMode, check.ExpectedMode)
		}
	}

	// Only config file should have wrong permissions
	if result.Failed != 1 {
		t.Errorf("Expected 1 failed check, got %d", result.Failed)
	}

	// Verify specific file checks
	for _, check := range result.Checks {
		if strings.Contains(check.Rule.Path, "config") && !check.NeedsChange {
			t.Error("Expected config file to need permission change")
		}
		if strings.Contains(check.Rule.Path, "id_rsa") && check.NeedsChange {
			t.Error("Expected id_rsa to have correct permissions")
		}
	}
}

// TestCheckPermissions tests comprehensive permission checking
func TestCheckPermissions(t *testing.T) {
	tempDir := t.TempDir()

	// Create test SSH directory
	sshDir := filepath.Join(tempDir, ".ssh")
	os.Mkdir(sshDir, 0755) // Wrong permission

	pm := NewPermissionManager(&SecurityConfig{
		SSHDirectory: sshDir,
	})

	result, err := pm.CheckPermissions([]string{"ssh"})
	if err != nil {
		t.Fatalf("CheckPermissions failed: %v", err)
	}

	if !result.DryRun {
		t.Error("CheckPermissions should always be dry-run")
	}

	if len(result.Categories) != 1 || result.Categories[0] != "ssh" {
		t.Errorf("Expected categories [ssh], got %v", result.Categories)
	}

	if result.Summary.TotalFiles == 0 {
		t.Error("Expected at least one file checked")
	}
}

// TestPermissionManagerConcurrency tests concurrent operations
func TestPermissionManagerConcurrency(t *testing.T) {
	tempDir := t.TempDir()

	// Create multiple test files
	for i := 0; i < 10; i++ {
		path := filepath.Join(tempDir, fmt.Sprintf("file%d.txt", i))
		os.WriteFile(path, []byte("test"), 0644)
	}

	pm := NewPermissionManager(&SecurityConfig{
		DryRun: false,
	})

	// Run concurrent permission fixes
	done := make(chan bool, 10)

	for i := 0; i < 10; i++ {
		go func(index int) {
			defer func() { done <- true }()

			path := filepath.Join(tempDir, fmt.Sprintf("file%d.txt", index))
			check := pm.fixSinglePath(path, 0600, "test file", false)

			if check.Error != "" {
				t.Errorf("Concurrent fix failed: %v", check.Error)
			}
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	// Verify all files have correct permissions
	for i := 0; i < 10; i++ {
		path := filepath.Join(tempDir, fmt.Sprintf("file%d.txt", i))
		stat, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}

		mode := stat.Mode() & os.ModePerm
		if mode != 0600 {
			t.Errorf("File %s has incorrect permissions: %o", path, mode)
		}
	}
}

// TestFixPermissionsErrorHandling tests error handling during permission fixes
func TestFixPermissionsErrorHandling(t *testing.T) {
	pm := NewPermissionManager(nil)

	// Test with non-existent category
	result, err := pm.FixPermissions([]string{"invalid-category"})

	if err != nil {
		t.Errorf("Expected no error for invalid category, got: %v", err)
	}

	if result.Summary.TotalFiles != 0 {
		t.Error("Expected no files for invalid category")
	}

	// Test with inaccessible path
	if os.Geteuid() != 0 { // Skip if running as root
		result, err = pm.FixPermissions([]string{"system"})

		if err != nil {
			t.Errorf("Expected no error, got: %v", err)
		}

		// Should have some checks but may not have errors if files don't exist
		// This is environment-dependent, so we just verify it doesn't panic
		_ = result
	}
}

// TestPermissionRulesValidation tests validation of permission rules
func TestPermissionRulesValidation(t *testing.T) {
	// Test that all predefined rules have valid modes
	allRules := append(SSHPermissionRules, SystemPermissionRules...)
	allRules = append(allRules, SSLPermissionRules...)

	for _, rule := range allRules {
		if rule.Path == "" {
			t.Errorf("Rule with empty path: %+v", rule)
		}

		if rule.Description == "" {
			t.Errorf("Rule without description: %+v", rule)
		}

		if rule.Category == "" {
			t.Errorf("Rule without category: %+v", rule)
		}

		// Check mode is reasonable (between 0000 and 0777 + special bits)
		if rule.Mode > 07777 {
			t.Errorf("Invalid mode %o for rule %s", rule.Mode, rule.Path)
		}
	}
}

// TestBackupCreation tests backup functionality
func TestBackupCreation(t *testing.T) {
	tempDir := t.TempDir()
	backupDir := filepath.Join(tempDir, "backups")
	testFile := filepath.Join(tempDir, "test.txt")

	// Create test file
	os.WriteFile(testFile, []byte("test"), 0644)

	pm := NewPermissionManager(&SecurityConfig{
		DryRun:          false,
		CreateBackups:   true,
		BackupDirectory: backupDir,
	})

	// Fix permissions (should create backup)
	before := time.Now()
	check := pm.fixSinglePath(testFile, 0600, "test file", true)

	if check.Error != "" {
		t.Fatalf("Fix failed: %v", check.Error)
	}

	// Verify backup was created
	entries, err := os.ReadDir(backupDir)
	if err != nil {
		t.Fatalf("Failed to read backup directory: %v", err)
	}

	if len(entries) != 1 {
		t.Fatalf("Expected 1 backup file, found %d", len(entries))
	}

	// Verify backup content
	backupFile := filepath.Join(backupDir, entries[0].Name())
	content, err := os.ReadFile(backupFile)
	if err != nil {
		t.Fatalf("Failed to read backup file: %v", err)
	}

	expectedContent := fmt.Sprintf("%s: 644\n", testFile)
	if string(content) != expectedContent {
		t.Errorf("Backup content = %q, want %q", string(content), expectedContent)
	}

	// Verify backup timestamp
	info, _ := entries[0].Info()
	if info.ModTime().Before(before) || info.ModTime().After(time.Now()) {
		t.Error("Backup file has incorrect timestamp")
	}
}
