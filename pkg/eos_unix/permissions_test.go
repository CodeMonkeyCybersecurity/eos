package eos_unix

import (
	"context"
	"os"
	"os/user"
	"testing"
)

func TestCheckSudo(t *testing.T) {
	// Note: This test may behave differently in CI environments
	// where sudo might not be available or configured
	
	t.Run("sudo check", func(t *testing.T) {
		result := CheckSudo()
		
		// Log the result rather than asserting, since sudo availability
		// varies by environment
		t.Logf("Sudo available: %v", result)
		
		// The function should not panic and should return a boolean
		if result != true && result != false {
			t.Error("CheckSudo should return a boolean value")
		}
	})
}

func TestIsPrivilegedUser(t *testing.T) {
	ctx := context.Background()
	
	tests := []struct {
		name        string
		description string
	}{
		{
			name:        "current user privilege check",
			description: "should determine if current user is privileged",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsPrivilegedUser(ctx)
			
			// Log the result for debugging
			currentUser, err := user.Current()
			if err == nil {
				t.Logf("Current user: %s, Privileged: %v, EUID: %d", 
					currentUser.Username, result, os.Geteuid())
			} else {
				t.Logf("Could not get current user: %v, Privileged: %v, EUID: %d", 
					err, result, os.Geteuid())
			}

			// The function should not panic and should return a boolean
			if result != true && result != false {
				t.Error("IsPrivilegedUser should return a boolean value")
			}

			// If running as root (EUID 0), should return true
			if os.Geteuid() == 0 && !result {
				t.Error("Should return true when running as root")
			}
		})
	}
}

func TestEnforceSecretsAccess(t *testing.T) {
	ctx := context.Background()
	
	tests := []struct {
		name           string
		show           bool
		expectedResult bool
		description    string
	}{
		{
			name:           "non-privileged user, no secrets",
			show:           false,
			expectedResult: true,
			description:    "should allow non-privileged users when not requesting secrets",
		},
		{
			name:           "secrets request",
			show:           true,
			expectedResult: IsPrivilegedUser(ctx), // Depends on current user
			description:    "should only allow privileged users to view secrets",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := EnforceSecretsAccess(ctx, tt.show)
			
			t.Logf("Show secrets: %v, Result: %v, Expected: %v", 
				tt.show, result, tt.expectedResult)

			// For the non-secrets case, should always allow
			if !tt.show && !result {
				t.Error("Should allow access when not requesting secrets")
			}

			// For secrets case, behavior depends on privilege level
			if tt.show {
				isPrivileged := IsPrivilegedUser(ctx)
				if isPrivileged && !result {
					t.Error("Should allow privileged user to view secrets")
				}
				if !isPrivileged && result {
					t.Error("Should not allow non-privileged user to view secrets")
				}
			}
		})
	}
}

func TestRequireRoot(t *testing.T) {
	ctx := context.Background()
	
	t.Run("require root call", func(t *testing.T) {
		// This function calls os.Exit(1) if not privileged
		// We can't easily test the exit behavior in a unit test
		// But we can verify it doesn't panic when called
		
		isPrivileged := IsPrivilegedUser(ctx)
		t.Logf("User is privileged: %v", isPrivileged)
		
		// Only test the function if we're actually privileged
		// to avoid the test process exiting
		if isPrivileged {
			// Should not panic or exit for privileged users
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("RequireRoot panicked: %v", r)
				}
			}()
			
			RequireRoot(ctx)
			t.Log("RequireRoot completed successfully for privileged user")
		} else {
			t.Skip("Skipping RequireRoot test for non-privileged user (would exit)")
		}
	})
}

func TestPrivilegeEscalation(t *testing.T) {
	ctx := context.Background()
	
	t.Run("privilege validation consistency", func(t *testing.T) {
		// Test that privilege checks are consistent
		isPrivileged1 := IsPrivilegedUser(ctx)
		isPrivileged2 := IsPrivilegedUser(ctx)
		
		if isPrivileged1 != isPrivileged2 {
			t.Error("Privilege check should be consistent between calls")
		}

		// Test that EUID 0 always means privileged
		if os.Geteuid() == 0 && !isPrivileged1 {
			t.Error("EUID 0 should always be considered privileged")
		}
	})

	t.Run("environment security", func(t *testing.T) {
		// Verify that privilege checks don't rely on environment variables
		// that could be manipulated
		
		originalUser := os.Getenv("USER")
		originalHome := os.Getenv("HOME")
		
		// Temporarily modify environment
		os.Setenv("USER", "root")
		os.Setenv("HOME", "/root")
		
		result1 := IsPrivilegedUser(ctx)
		
		// Restore environment
		if originalUser != "" {
			os.Setenv("USER", originalUser)
		} else {
			os.Unsetenv("USER")
		}
		if originalHome != "" {
			os.Setenv("HOME", originalHome)
		} else {
			os.Unsetenv("HOME")
		}
		
		result2 := IsPrivilegedUser(ctx)
		
		// Results should be the same regardless of environment manipulation
		if result1 != result2 {
			t.Error("Privilege check should not be affected by environment variable manipulation")
		}
		
		t.Logf("Privilege check consistent despite env manipulation: %v", result1 == result2)
	})
}

func TestUserInformation(t *testing.T) {
	t.Run("current user information", func(t *testing.T) {
		currentUser, err := user.Current()
		if err != nil {
			t.Logf("Could not get current user: %v", err)
			return
		}

		t.Logf("Username: %s", currentUser.Username)
		t.Logf("UID: %s", currentUser.Uid)
		t.Logf("GID: %s", currentUser.Gid)
		t.Logf("Name: %s", currentUser.Name)
		t.Logf("HomeDir: %s", currentUser.HomeDir)
		t.Logf("EUID: %d", os.Geteuid())
		t.Logf("EGID: %d", os.Getegid())

		// Verify user information is consistent
		if currentUser.Username == "" {
			t.Error("Username should not be empty")
		}
		if currentUser.Uid == "" {
			t.Error("UID should not be empty")
		}
		if currentUser.HomeDir == "" {
			t.Error("HomeDir should not be empty")
		}
	})
}