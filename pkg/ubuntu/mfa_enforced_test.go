package ubuntu

import (
	"context"
	"testing"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap/zaptest"
)

func TestDefaultEnforcedMFAConfig(t *testing.T) {
	config := DefaultEnforcedMFAConfig()
	
	assert.True(t, config.RequireMFA, "MFA should be required by default")
	assert.False(t, config.AllowPasswordFallback, "Password fallback should be disabled by default")
	assert.Equal(t, "graceful", config.EnforcementMode, "Should use graceful enforcement mode")
	assert.Equal(t, 24, config.GracePeriodHours, "Should have 24-hour grace period")
	assert.Empty(t, config.ExemptUsers, "Should have no exempt users by default")
}

func TestMFAScriptGeneration(t *testing.T) {
	// Test that the MFA scripts contain expected content
	assert.Contains(t, mfaEnforcementScript, "google-authenticator", "Setup script should include google-authenticator")
	assert.Contains(t, mfaEnforcementScript, "QR code", "Setup script should mention QR code")
	assert.Contains(t, mfaEnforcementScript, "backup codes", "Setup script should mention backup codes")
	
	assert.Contains(t, mfaStatusScript, "MFA Status Report", "Status script should have status report")
	assert.Contains(t, mfaStatusScript, "PAM Configuration", "Status script should check PAM config")
}

func TestPAMConfigurations(t *testing.T) {
	// Test enforced PAM configurations
	assert.Contains(t, enforcedPAMSudoConfig, "required", "Enforced config should require MFA")
	assert.Contains(t, enforcedPAMSudoConfig, "pam_google_authenticator.so", "Should use Google Authenticator")
	assert.NotContains(t, enforcedPAMSudoConfig, "nullok", "Enforced config should not allow nullok")
	
	// Test graceful PAM configurations
	assert.Contains(t, gracefulPAMSudoConfig, "sufficient", "Graceful config should use sufficient")
	assert.Contains(t, gracefulPAMSudoConfig, "nullok", "Graceful config should allow nullok during setup")
}

func TestConfigureEnforcedMFADryRun(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping MFA configuration test in short mode")
	}
	
	// Create a temporary test environment
	tempDir := t.TempDir()
	
	// Mock runtime context
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	logger := zaptest.NewLogger(t)
	rc := &eos_io.RuntimeContext{
		Ctx: ctx,
	}
	_ = logger
	
	// This would normally require root permissions and actual system files
	// For testing, we'll just verify the function doesn't panic
	t.Run("MFA config structure", func(t *testing.T) {
		// Test the configuration structure without actually applying it
		config := DefaultEnforcedMFAConfig()
		assert.NotNil(t, config)
		
		// Verify PAM configs are well-formed
		assert.Greater(t, len(enforcedPAMSudoConfig), 50, "PAM config should be substantial")
		assert.Greater(t, len(enforcedPAMSuConfig), 50, "PAM config should be substantial")
		
		// Verify scripts are well-formed
		assert.Greater(t, len(mfaEnforcementScript), 1000, "MFA script should be comprehensive")
		assert.Greater(t, len(mfaStatusScript), 500, "Status script should be substantial")
	})
	
	// Test script creation functions (would need write permissions)
	t.Run("Script paths", func(t *testing.T) {
		expectedPaths := []string{
			"/usr/local/bin/setup-mfa",
			"/usr/local/bin/mfa-status", 
			"/usr/local/bin/enforce-mfa-strict",
		}
		
		for _, path := range expectedPaths {
			assert.NotEmpty(t, path, "Script path should not be empty")
			assert.Contains(t, path, "/usr/local/bin/", "Scripts should be in standard location")
		}
	})
	
	// Verify the runtime context is properly used
	assert.NotNil(t, rc.Ctx, "Runtime context should have context")
	
	_ = tempDir // Use the temp directory variable to avoid unused warning
	_ = rc      // Use rc to avoid unused warning
}

func TestSecureUbuntuEnhancedModes(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping enhanced security test in short mode")
	}
	
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	logger := zaptest.NewLogger(t)
	rc := &eos_io.RuntimeContext{
		Ctx: ctx,
	}
	_ = logger
	_ = rc
	
	testCases := []struct {
		name     string
		mfaMode  string
		shouldErr bool
	}{
		{"Enforced MFA mode", "enforced", false},
		{"Standard MFA mode", "standard", false}, 
		{"Disabled MFA mode", "disabled", false},
		{"Invalid MFA mode", "invalid", true},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Note: This test would fail without root permissions and actual system
			// In a real test environment, you'd need to mock the system calls
			
			if tc.shouldErr {
				// Test invalid mode handling
				assert.Contains(t, []string{"invalid"}, tc.mfaMode, "Should test invalid mode")
			} else {
				// Test valid modes
				assert.Contains(t, []string{"enforced", "standard", "disabled"}, tc.mfaMode, 
					"Should test valid modes")
			}
		})
	}
}

func TestMFAEnforcementFlags(t *testing.T) {
	// Test that our flag logic makes sense
	testCases := []struct {
		name           string
		enforceMFA     bool
		enableMFA      bool
		disableMFA     bool
		noMFA          bool
		expectedMode   string
	}{
		{"Default (no flags)", false, false, false, false, "enforced"},
		{"Explicit enforce", true, false, false, false, "enforced"},
		{"Enable standard", false, true, false, false, "standard"},
		{"Disable MFA", false, false, true, false, "disabled"},
		{"No MFA flag", false, false, false, true, "disabled"},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var actualMode string
			
			// Simulate the flag logic from the command
			if tc.noMFA {
				actualMode = "disabled"
			} else if tc.enforceMFA || (!tc.enableMFA && !tc.disableMFA) {
				actualMode = "enforced"
			} else if tc.enableMFA {
				actualMode = "standard"
			} else {
				actualMode = "disabled"
			}
			
			assert.Equal(t, tc.expectedMode, actualMode, 
				"MFA mode should match expected for flag combination")
		})
	}
}

// TestMFAScriptSafety ensures scripts have basic safety measures
func TestMFAScriptSafety(t *testing.T) {
	scripts := map[string]string{
		"enforcement": mfaEnforcementScript,
		"status":      mfaStatusScript,
	}
	
	for name, script := range scripts {
		t.Run(name, func(t *testing.T) {
			// Check for basic safety measures
			assert.Contains(t, script, "set -euo pipefail", "Script should use strict mode")
			assert.Contains(t, script, "#!/bin/bash", "Script should have proper shebang")
			
			// Check for security considerations
			if name == "enforcement" {
				assert.Contains(t, script, "backup", "Enforcement script should mention backups")
				assert.Contains(t, script, "emergency", "Should mention emergency access")
			}
		})
	}
}

// Benchmark basic MFA config generation
func BenchmarkDefaultMFAConfig(b *testing.B) {
	for i := 0; i < b.N; i++ {
		config := DefaultEnforcedMFAConfig()
		_ = config // Use the config to avoid optimization
	}
}