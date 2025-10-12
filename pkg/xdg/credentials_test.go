// pkg/xdg/credentials_test.go - Security-focused tests for credential storage
package xdg

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSaveCredential tests credential saving functionality
func TestSaveCredential(t *testing.T) {
	// Set up test environment
	tempDir := t.TempDir()
	_ = os.Setenv("XDG_CONFIG_HOME", tempDir)
	defer func() { _ = os.Unsetenv("XDG_CONFIG_HOME") }()

	tests := []struct {
		name          string
		app           string
		username      string
		password      string
		expectError   bool
		errorContains string
		checkFile     bool
	}{
		{
			name:        "save_basic_credential",
			app:         "testapp",
			username:    "user1",
			password:    "password123",
			expectError: false,
			checkFile:   true,
		},
		{
			name:        "save_empty_password",
			app:         "testapp",
			username:    "user2",
			password:    "",
			expectError: false,
			checkFile:   true,
		},
		{
			name:        "save_with_special_chars",
			app:         "testapp",
			username:    "user@domain.com",
			password:    "p@ssw0rd!#$%^&*()",
			expectError: false,
			checkFile:   true,
		},
		{
			name:        "save_with_newlines",
			app:         "testapp",
			username:    "user3",
			password:    "password\nwith\nnewlines",
			expectError: false,
			checkFile:   true,
		},
		{
			name:        "save_unicode_password",
			app:         "testapp",
			username:    "user4",
			password:    "пароль密码🔐",
			expectError: false,
			checkFile:   true,
		},
		{
			name:          "empty_app_name",
			app:           "",
			username:      "user",
			password:      "pass",
			expectError:   false, // Currently allows empty app
			checkFile:     true,
		},
		{
			name:          "empty_username",
			app:           "testapp",
			username:      "",
			password:      "pass",
			expectError:   false, // Currently allows empty username
			checkFile:     true,
		},
		{
			name:        "path_traversal_in_username",
			app:         "testapp",
			username:    "../../../etc/passwd",
			password:    "malicious",
			expectError: false, // Currently doesn't prevent this!
			checkFile:   true,
		},
		{
			name:        "very_long_password",
			app:         "testapp",
			username:    "user5",
			password:    strings.Repeat("a", 10000),
			expectError: false,
			checkFile:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path, err := SaveCredential(tt.app, tt.username, tt.password)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				assert.NoError(t, err)
				assert.NotEmpty(t, path)

				if tt.checkFile {
					// Verify file exists
					info, err := os.Stat(path)
					require.NoError(t, err)

					// Check permissions
					perms := info.Mode().Perm()
					assert.Equal(t, fs.FileMode(0600), perms, 
						"Credential file should have 0600 permissions")

					// Check directory permissions
					dir := filepath.Dir(path)
					dirInfo, err := os.Stat(dir)
					require.NoError(t, err)
					dirPerms := dirInfo.Mode().Perm()
					assert.Equal(t, fs.FileMode(0700), dirPerms,
						"Credential directory should have 0700 permissions")

					// Read and verify content
					content, err := os.ReadFile(path)
					require.NoError(t, err)
					assert.Equal(t, tt.password, string(content))

					// Verify filename format
					expectedFile := fmt.Sprintf("%s.secret", tt.username)
					assert.True(t, strings.HasSuffix(path, expectedFile))
				}
			}
		})
	}
}

// TestCredentialSecurity tests security aspects of credential storage
func TestCredentialSecurity(t *testing.T) {
	tempDir := t.TempDir()
	_ = os.Setenv("XDG_CONFIG_HOME", tempDir)
	defer func() { _ = os.Unsetenv("XDG_CONFIG_HOME") }()

	t.Run("plaintext_storage_vulnerability", func(t *testing.T) {
		// This test documents a CRITICAL security issue
		password := "super-secret-password"
		path, err := SaveCredential("app", "user", password)
		require.NoError(t, err)

		// Read the file directly
		content, err := os.ReadFile(path)
		require.NoError(t, err)

		// Password is stored in plaintext - SECURITY VULNERABILITY!
		assert.Equal(t, password, string(content))
		t.Error("CRITICAL: Passwords are stored in plaintext without encryption")
	})

	t.Run("world_readable_prevention", func(t *testing.T) {
		path, err := SaveCredential("secureapp", "user", "password")
		require.NoError(t, err)

		// Try to make file world-readable
		err = os.Chmod(path, 0644)
		require.NoError(t, err)

		// Verify it's now world-readable (this is bad!)
		info, err := os.Stat(path)
		require.NoError(t, err)
		assert.Equal(t, fs.FileMode(0644), info.Mode().Perm())
		
		t.Log("WARNING: No protection against permission changes after creation")
	})

	t.Run("directory_traversal_vulnerability", func(t *testing.T) {
		// Test path traversal in username
		maliciousUsername := "../../outside/config"
		path, err := SaveCredential("app", maliciousUsername, "gotcha")
		
		// Currently this succeeds - SECURITY ISSUE!
		assert.NoError(t, err)
		assert.Contains(t, path, "..")
		t.Error("CRITICAL: Path traversal in username is not prevented")
	})

	t.Run("symlink_attack", func(t *testing.T) {
		// Create a symlink target
		targetDir := filepath.Join(tempDir, "target")
		err := os.MkdirAll(targetDir, 0755)
		require.NoError(t, err)

		// Create symlink in config path
		configBase := filepath.Join(tempDir, "app", "credentials")
		err = os.MkdirAll(filepath.Dir(configBase), 0700)
		require.NoError(t, err)
		
		err = os.Symlink(targetDir, configBase)
		if err == nil {
			// If symlink creation succeeded, test the vulnerability
			_, err := SaveCredential("app", "user", "leaked")
			assert.NoError(t, err)
			
			// Check if file was created in symlink target
			targetFile := filepath.Join(targetDir, "user.secret")
			if _, err := os.Stat(targetFile); err == nil {
				t.Error("CRITICAL: Symlink attack succeeded - credentials written to symlink target")
			}
		}
	})

	t.Run("concurrent_access_race_condition", func(t *testing.T) {
		const goroutines = 10
		errors := make([]error, goroutines)
		paths := make([]string, goroutines)
		var wg sync.WaitGroup

		for i := 0; i < goroutines; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				// All writing to same file
				path, err := SaveCredential("raceapp", "shareduser", fmt.Sprintf("password%d", idx))
				errors[idx] = err
				paths[idx] = path
			}(i)
		}

		wg.Wait()

		// Check for errors
		successCount := 0
		for i, err := range errors {
			if err == nil {
				successCount++
				t.Logf("Goroutine %d succeeded with path: %s", i, paths[i])
			}
		}

		// All should succeed (but last write wins)
		assert.Equal(t, goroutines, successCount)
		
		// Read final content
		finalPath := paths[0] // All should have same path
		content, err := os.ReadFile(finalPath)
		require.NoError(t, err)
		
		t.Logf("Final password in file: %s", string(content))
		t.Log("WARNING: No protection against concurrent writes - last write wins")
	})

	t.Run("memory_security", func(t *testing.T) {
		// This documents that passwords are passed as strings
		// which remain in memory until garbage collected
		sensitivePassword := "this-stays-in-memory"
		_, err := SaveCredential("memapp", "user", sensitivePassword)
		assert.NoError(t, err)
		
		// In languages like Go, we can't easily clear string memory
		t.Log("WARNING: Passwords remain in memory as immutable strings")
	})
}

// TestCredentialFileNaming tests filename generation
func TestCredentialFileNaming(t *testing.T) {
	tempDir := t.TempDir()
	_ = os.Setenv("XDG_CONFIG_HOME", tempDir)
	defer func() { _ = os.Unsetenv("XDG_CONFIG_HOME") }()

	tests := []struct {
		name             string
		username         string
		expectedFilename string
		shouldSanitize   bool
	}{
		{
			name:             "basic_username",
			username:         "john",
			expectedFilename: "john.secret",
			shouldSanitize:   false,
		},
		{
			name:             "email_username",
			username:         "user@example.com",
			expectedFilename: "user@example.com.secret",
			shouldSanitize:   true, // Should sanitize @ but doesn't
		},
		{
			name:             "username_with_slash",
			username:         "domain/user",
			expectedFilename: "domain/user.secret",
			shouldSanitize:   true, // Creates subdirectory!
		},
		{
			name:             "username_with_dots",
			username:         "../../../etc/passwd",
			expectedFilename: "../../../etc/passwd.secret",
			shouldSanitize:   true, // Path traversal!
		},
		{
			name:             "unicode_username",
			username:         "用户名",
			expectedFilename: "用户名.secret",
			shouldSanitize:   false,
		},
		{
			name:             "null_byte_injection",
			username:         "user\x00.txt",
			expectedFilename: "user\x00.txt.secret",
			shouldSanitize:   true, // Null byte attack!
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path, err := SaveCredential("naming-test", tt.username, "password")
			
			if tt.shouldSanitize {
				// These SHOULD be sanitized but currently aren't
				assert.NoError(t, err) // Currently succeeds
				assert.Contains(t, path, tt.expectedFilename)
				t.Errorf("Username '%s' should be sanitized but isn't", tt.username)
			} else {
				assert.NoError(t, err)
				assert.True(t, strings.HasSuffix(path, tt.expectedFilename))
			}
		})
	}
}

// TestCredentialDirectoryStructure tests directory creation
func TestCredentialDirectoryStructure(t *testing.T) {
	tempDir := t.TempDir()
	_ = os.Setenv("XDG_CONFIG_HOME", tempDir)
	defer func() { _ = os.Unsetenv("XDG_CONFIG_HOME") }()

	t.Run("nested_directory_creation", func(t *testing.T) {
		// Test with app name containing slashes
		_, err := SaveCredential("company/product/component", "user", "pass")
		assert.NoError(t, err)

		// Verify nested structure was created
		expectedDir := filepath.Join(tempDir, "company", "product", "component", "credentials")
		info, err := os.Stat(expectedDir)
		require.NoError(t, err)
		assert.True(t, info.IsDir())
		assert.Equal(t, fs.FileMode(0700), info.Mode().Perm())
	})

	t.Run("permission_inheritance", func(t *testing.T) {
		// Create parent with different permissions
		parentDir := filepath.Join(tempDir, "permtest")
		err := os.MkdirAll(parentDir, 0755)
		require.NoError(t, err)

		// Save credential
		_ = os.Setenv("XDG_CONFIG_HOME", parentDir)
		path, err := SaveCredential("app", "user", "pass")
		assert.NoError(t, err)

		// Check that credentials dir has correct permissions
		credDir := filepath.Dir(path)
		info, err := os.Stat(credDir)
		require.NoError(t, err)
		assert.Equal(t, fs.FileMode(0700), info.Mode().Perm(),
			"Credentials directory should have 0700 regardless of parent")
	})
}

// TestErrorScenarios tests error handling
func TestErrorScenarios(t *testing.T) {
	t.Run("read_only_filesystem", func(t *testing.T) {
		if os.Getuid() == 0 {
			t.Skip("Cannot test read-only filesystem as root")
		}

		// Try to write to a read-only location
		_ = os.Setenv("XDG_CONFIG_HOME", "/proc")
		_, err := SaveCredential("app", "user", "pass")
		assert.Error(t, err)
		_ = os.Unsetenv("XDG_CONFIG_HOME")
	})

	t.Run("disk_full_simulation", func(t *testing.T) {
		// This is hard to simulate portably
		t.Skip("Disk full simulation not implemented")
	})

	t.Run("invalid_filename_characters", func(t *testing.T) {
		tempDir := t.TempDir()
		_ = os.Setenv("XDG_CONFIG_HOME", tempDir)
		defer os.Unsetenv("XDG_CONFIG_HOME")

		// Test with null byte in username
		if strings.Contains("\x00", "") {
			// Some systems might handle this
			_, err := SaveCredential("app", "user\x00name", "pass")
			// Behavior is system-dependent
			_ = err
		}
	})
}

// BenchmarkSaveCredential benchmarks credential saving
func BenchmarkSaveCredential(b *testing.B) {
	tempDir := b.TempDir()
	_ = os.Setenv("XDG_CONFIG_HOME", tempDir)
	defer func() { _ = os.Unsetenv("XDG_CONFIG_HOME") }()

	b.Run("small_password", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = SaveCredential("benchapp", fmt.Sprintf("user%d", i), "smallpass")
		}
	})

	b.Run("large_password", func(b *testing.B) {
		largePassword := strings.Repeat("x", 1024)
		for i := 0; i < b.N; i++ {
			_, _ = SaveCredential("benchapp", fmt.Sprintf("user%d", i), largePassword)
		}
	})

	b.Run("concurrent_saves", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			i := 0
			for pb.Next() {
				_, _ = SaveCredential("benchapp", fmt.Sprintf("user%d", i), "pass")
				i++
			}
		})
	})
}

// TestSecurityRecommendations documents security improvements needed
func TestSecurityRecommendations(t *testing.T) {
	t.Run("encryption_required", func(t *testing.T) {
		t.Error("RECOMMENDATION: Implement encryption for stored passwords")
		t.Log("Suggested: Use age, gpg, or OS keyring for secure storage")
	})

	t.Run("input_sanitization_required", func(t *testing.T) {
		t.Error("RECOMMENDATION: Sanitize usernames to prevent path traversal")
		t.Log("Suggested: Replace '/', '\\', '..', and null bytes in usernames")
	})

	t.Run("memory_protection_required", func(t *testing.T) {
		t.Error("RECOMMENDATION: Use byte slices instead of strings for passwords")
		t.Log("Suggested: Allow zeroing password memory after use")
	})

	t.Run("atomic_writes_required", func(t *testing.T) {
		t.Error("RECOMMENDATION: Use atomic file writes to prevent corruption")
		t.Log("Suggested: Write to temp file and rename")
	})

	t.Run("audit_logging_required", func(t *testing.T) {
		t.Error("RECOMMENDATION: Add audit logging for credential access")
		t.Log("Suggested: Log (without passwords) who accessed credentials and when")
	})
}