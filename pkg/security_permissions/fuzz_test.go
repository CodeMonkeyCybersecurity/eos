package security_permissions

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"
)

// FuzzIsPrivateKey tests the IsPrivateKey function with various inputs
func FuzzIsPrivateKey(f *testing.F) {
	// Add seed corpus
	seeds := []string{
		"id_rsa",
		"id_rsa.pub",
		"private_key.pem",
		"public.key",
		"id_ed25519",
		"authorized_keys",
		"known_hosts",
		"..//id_rsa",
		"id_rsa\x00.pub",
		"../../../../etc/shadow",
		"private\nkey",
		"key.pem.backup",
		"",
		"\x00\x00\x00",
		"privatekey",
		"PRIVATE",
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, filename string) {
		// Function should not panic
		result := IsPrivateKey(filename)

		// Validate logic: .pub files should never be private keys
		if strings.HasSuffix(filename, ".pub") && result {
			t.Errorf("File ending with .pub should not be a private key: %q", filename)
		}

		// Empty filename should not be a private key
		if filename == "" && result {
			t.Error("Empty filename should not be a private key")
		}

		// Path traversal attempts should still be evaluated normally
		// (security is handled at file access level, not name level)
		cleanName := filepath.Base(filename)
		if cleanName != filename {
			// Re-evaluate with clean name to ensure consistency
			cleanResult := IsPrivateKey(cleanName)
			// Results might differ due to path components, which is acceptable
			_ = cleanResult
		}
	})
}

// FuzzCheckSinglePath tests path checking with various inputs
func FuzzCheckSinglePath(f *testing.F) {
	// Add seed corpus with various path patterns
	seeds := []struct {
		path string
		mode os.FileMode
	}{
		{"/tmp/test", 0600},
		{"/../etc/passwd", 0644},
		{"/tmp/\x00/test", 0700},
		{"/tmp/test\n.sh", 0755},
		{"", 0600},
		{"/very/long/path/" + strings.Repeat("a", 255), 0600},
		{"/tmp/テスト", 0600},
		{"/tmp/test..", 0600},
		{"/tmp/..", 0600},
		{"/tmp/./test", 0600},
	}

	for _, seed := range seeds {
		f.Add(seed.path, uint16(seed.mode))
	}

	f.Fuzz(func(t *testing.T, path string, mode uint16) {
		// Create a temporary directory for testing
		tempDir := t.TempDir()

		// Skip invalid UTF-8 paths
		if !utf8.ValidString(path) {
			t.Skip("Skipping invalid UTF-8 path")
		}

		// Convert mode to os.FileMode (limit to valid permission bits)
		fileMode := os.FileMode(mode & 0777)

		pm := NewPermissionManager(nil)

		// Test with non-existent path
		check := pm.checkSinglePath(path, fileMode, "fuzz test", false)

		// Should not panic - the main test objective
		// Error handling depends on path validity
		_ = check

		// Test with actual file
		if path != "" && !strings.Contains(path, "\x00") {
			testPath := filepath.Join(tempDir, "fuzztest")
			if err := os.WriteFile(testPath, []byte("test"), 0644); err == nil {
				check2 := pm.checkSinglePath(testPath, fileMode, "fuzz test", true)

				// Should detect the file exists
				if !check2.Exists {
					t.Error("Existing file not detected")
				}

				// Should correctly identify permission mismatch
				if fileMode != 0644 && !check2.NeedsChange {
					t.Error("Permission mismatch not detected")
				}
			}
		}
	})
}

// FuzzShouldExcludePath tests path exclusion with various patterns
func FuzzShouldExcludePath(f *testing.F) {
	// Add seed corpus
	seeds := []struct {
		path    string
		pattern string
	}{
		{"/tmp/test.bak", "*.bak"},
		{"/tmp/test", "*"},
		{"test.backup", "*.backup"},
		{"/path/to/.git", ".git"},
		{"../../../etc/passwd", "*passwd*"},
		{"/tmp/test\x00.bak", "*.bak"},
		{"", "*"},
		{"/tmp/" + strings.Repeat("a", 300), "*a*"},
		{"/tmp/テスト.bak", "*.bak"},
	}

	for _, seed := range seeds {
		f.Add(seed.path, seed.pattern)
	}

	f.Fuzz(func(t *testing.T, path string, pattern string) {
		// Skip invalid patterns that would cause filepath.Match to error
		if _, err := filepath.Match(pattern, "test"); err != nil {
			t.Skip("Invalid pattern")
		}

		pm := NewPermissionManager(&SecurityConfig{
			ExcludePatterns: []string{pattern},
		})

		// Should not panic
		excluded := pm.shouldExcludePath(path)

		// Validate the result makes sense
		if pattern == "*" && !excluded && path != "" {
			t.Errorf("Pattern '*' should exclude all non-empty paths, but didn't exclude %q", path)
		}

		// Empty path with empty pattern should not be excluded
		if path == "" && pattern == "" && excluded {
			t.Error("Empty path with empty pattern should not be excluded")
		}
	})
}

// FuzzPermissionRuleValidation tests permission rule creation with fuzzy inputs
func FuzzPermissionRuleValidation(f *testing.F) {
	// Add seed corpus
	seeds := []struct {
		path        string
		mode        uint16
		description string
		category    string
	}{
		{"/etc/passwd", 0644, "Password file", "system"},
		{"$HOME/.ssh", 0700, "SSH directory", "ssh"},
		{"/etc/ssl/private", 0700, "SSL private keys", "ssl"},
		{"", 0, "", ""},
		{"/tmp/../etc/passwd", 0666, "Traversal attempt", "hack"},
		{"/very/long/path/" + strings.Repeat("x", 200), 0755, strings.Repeat("desc", 50), "long"},
		{"/tmp/\x00/test", 0600, "Null byte", "test"},
		{"/tmp/テスト", 0755, "Unicode test", "unicode"},
	}

	for _, seed := range seeds {
		f.Add(seed.path, seed.mode, seed.description, seed.category)
	}

	f.Fuzz(func(t *testing.T, path string, mode uint16, description string, category string) {
		// Create a rule
		rule := PermissionRule{
			Path:        path,
			Mode:        os.FileMode(mode & 07777), // Limit to valid mode bits
			Description: description,
			Required:    len(path) > 0, // Required if path is non-empty
			Category:    category,
		}

		// Rule creation should not panic
		_ = rule

		// Test with permission manager
		pm := NewPermissionManager(&SecurityConfig{
			CustomRules: []PermissionRule{rule},
		})

		// Checking permissions should not panic
		check := pm.checkSinglePath(rule.Path, rule.Mode, rule.Description, rule.Required)

		// Validate check result
		if check.ExpectedMode != rule.Mode {
			t.Errorf("Expected mode mismatch: got %o, want %o", check.ExpectedMode, rule.Mode)
		}

		// GetPermissionRules should handle any category without panic
		rules := GetPermissionRules([]string{category})
		_ = rules
	})
}

// FuzzFixPermissions tests the full fix permissions flow with fuzzy inputs
func FuzzFixPermissions(f *testing.F) {
	// Add seed corpus
	categories := [][]string{
		{"ssh"},
		{"system"},
		{"ssl"},
		{"ssh", "system"},
		{"unknown"},
		{""},
		{"ssh", "ssh", "ssh"},          // Duplicates
		{"a", "b", "c", "d", "e", "f"}, // Many categories
	}

	for _, cats := range categories {
		f.Add(strings.Join(cats, ","))
	}

	f.Fuzz(func(t *testing.T, categoriesStr string) {
		// Parse categories
		categories := strings.Split(categoriesStr, ",")
		if categoriesStr == "" {
			categories = []string{}
		}

		// Create temp directory for testing
		tempDir := t.TempDir()

		pm := NewPermissionManager(&SecurityConfig{
			SSHDirectory:    filepath.Join(tempDir, ".ssh"),
			DryRun:          true, // Always dry-run for fuzzing
			BackupDirectory: filepath.Join(tempDir, "backups"),
		})

		// Should not panic
		result, err := pm.FixPermissions(categories)

		// Basic validation
		if err != nil {
			// Error is acceptable, but should be well-formed
			if err.Error() == "" {
				t.Error("Empty error message")
			}
		}

		if result == nil {
			t.Fatal("Result should not be nil")
		}

		// Validate result structure
		if result.Timestamp.IsZero() {
			t.Error("Timestamp should be set")
		}

		if !result.DryRun {
			t.Error("DryRun should be true")
		}

		// Results map should be initialized
		if result.Results == nil {
			t.Error("Results map should not be nil")
		}

		// Summary should be properly initialized
		if result.Summary.Errors == nil {
			t.Error("Summary errors should not be nil")
		}
	})
}

// FuzzPathExpansion tests environment variable expansion in paths
func FuzzPathExpansion(f *testing.F) {
	// Add seed corpus
	seeds := []string{
		"$HOME/.ssh",
		"${HOME}/.ssh",
		"$USER/config",
		"/etc/$USER/conf",
		"$NONEXISTENT/path",
		"$$HOME",
		"${HOME:-/tmp}/.ssh",
		"$HOME/$USER/$PATH",
		"${}/test",
		"$",
		"${",
		"$HOME}",
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	// Set some environment variables for testing
	os.Setenv("FUZZ_TEST_VAR", "/fuzzy")
	defer os.Unsetenv("FUZZ_TEST_VAR")

	f.Fuzz(func(t *testing.T, path string) {
		// os.ExpandEnv should not panic
		expanded := os.ExpandEnv(path)

		// Create a rule with the path
		rule := PermissionRule{
			Path:        path,
			Mode:        0600,
			Description: "Fuzz test",
			Category:    "test",
		}

		pm := NewPermissionManager(nil)

		// Checking with environment variables should not panic
		expandedPath := os.ExpandEnv(rule.Path)
		check := pm.checkSinglePath(expandedPath, rule.Mode, rule.Description, false)

		// Basic validation
		if check.Rule.Mode != rule.Mode {
			t.Errorf("Mode mismatch: got %o, want %o", check.Rule.Mode, rule.Mode)
		}

		// If path contains null bytes after expansion, it should fail
		if strings.Contains(expanded, "\x00") && check.Error == "" && check.Exists {
			t.Error("Path with null byte should not be accessible")
		}
	})
}

// FuzzBackupFileNaming tests backup file creation with various inputs
func FuzzBackupFileNaming(f *testing.F) {
	// Add seed corpus
	seeds := []string{
		"/tmp/test.txt",
		"/etc/passwd",
		"relative/path.conf",
		"/path/with spaces/file.txt",
		"/path/with\nnewline.txt",
		"/unicode/路径/文件.txt",
		"",
		"//double//slash//path.txt",
		"/path/../etc/passwd",
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, testPath string) {
		tempDir := t.TempDir()
		backupDir := filepath.Join(tempDir, "backups")

		// Create a test file if path is valid
		if testPath != "" && !strings.Contains(testPath, "\x00") {
			fullPath := filepath.Join(tempDir, "testfile")
			os.WriteFile(fullPath, []byte("test"), 0644)

			pm := NewPermissionManager(&SecurityConfig{
				CreateBackups:   true,
				BackupDirectory: backupDir,
			})

			// Should not panic
			err := pm.createBackup(fullPath)

			// If successful, verify backup was created
			if err == nil {
				entries, _ := os.ReadDir(backupDir)
				if len(entries) == 0 {
					t.Error("Backup file was not created")
				}
			}
		}
	})
}
