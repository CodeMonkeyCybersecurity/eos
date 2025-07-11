package ragequit

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/ragequit/diagnostics"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/ragequit/emergency"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/ragequit/recovery"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/ragequit/system"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRagequitCommand(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		expectError bool
	}{
		{
			name:        "help flag",
			args:        []string{"--help"},
			expectError: false,
		},
		{
			name:        "no-reboot flag",
			args:        []string{"--no-reboot", "--force", "--reason", "test"},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary directory for test
			tempDir := t.TempDir()
			originalHome := os.Getenv("HOME")
			defer func() {
				if originalHome != "" {
					_ = os.Setenv("HOME", originalHome)
				} else {
					_ = os.Unsetenv("HOME")
				}
			}()
			_ = os.Setenv("HOME", tempDir)

			// Use the actual RagequitCmd
			cmd := RagequitCmd

			// Set arguments
			cmd.SetArgs(tt.args)

			// Execute command
			err := cmd.Execute()

			if tt.expectError {
				assert.Error(t, err)
			} else {
				if tt.args[0] != "--help" {
					// For actual execution, we expect it to succeed with --no-reboot
					assert.NoError(t, err)
				}
			}
		})
	}
}

func TestUtilityFunctions(t *testing.T) {
	t.Run("getHostname", func(t *testing.T) {
		hostname := system.GetHostname()
		assert.NotEmpty(t, hostname)
		assert.NotEqual(t, "unknown", hostname)
	})

	t.Run("getHomeDir", func(t *testing.T) {
		homeDir := system.GetHomeDir()
		assert.NotEmpty(t, homeDir)
	})

	t.Run("fileExists", func(t *testing.T) {
		// Test with existing file
		tempFile := filepath.Join(t.TempDir(), "test-file")
		err := os.WriteFile(tempFile, []byte("test"), 0644)
		require.NoError(t, err)
		
		assert.True(t, system.FileExists(tempFile))
		assert.False(t, system.FileExists("/nonexistent/file"))
	})

	t.Run("dirExists", func(t *testing.T) {
		tempDir := t.TempDir()
		assert.True(t, system.DirExists(tempDir))
		assert.False(t, system.DirExists("/nonexistent/directory"))
	})

	t.Run("commandExists", func(t *testing.T) {
		// Test with a command that should exist on most systems
		assert.True(t, system.CommandExists("echo"))
		assert.False(t, system.CommandExists("nonexistent-command-12345"))
	})

	t.Run("readFile", func(t *testing.T) {
		tempFile := filepath.Join(t.TempDir(), "test-content")
		testContent := "test file content"
		err := os.WriteFile(tempFile, []byte(testContent), 0644)
		require.NoError(t, err)

		content := system.ReadFile(tempFile)
		assert.Equal(t, testContent, content)

		// Test with nonexistent file
		emptyContent := system.ReadFile("/nonexistent/file")
		assert.Empty(t, emptyContent)
	})

	t.Run("runCommandWithTimeout", func(t *testing.T) {
		// Test successful command
		output := system.RunCommandWithTimeout("echo", []string{"hello", "world"}, 5*time.Second)
		assert.Contains(t, output, "hello world")

		// Test command timeout
		output = system.RunCommandWithTimeout("sleep", []string{"10"}, 100*time.Millisecond)
		assert.Empty(t, output)

		// Test nonexistent command
		output = system.RunCommandWithTimeout("nonexistent-command", []string{}, 5*time.Second)
		assert.Empty(t, output)
	})
}

func TestCreateTimestampFile(t *testing.T) {
	tempDir := t.TempDir()
	originalHome := os.Getenv("HOME")
	defer func() {
		if originalHome != "" {
			_ = os.Setenv("HOME", originalHome)
		} else {
			_ = os.Unsetenv("HOME")
		}
	}()
	_ = os.Setenv("HOME", tempDir)

	rc := eos_io.NewContext(context.Background(), "test")

	testReason := "test emergency"
	emergency.CreateTimestampFile(rc, testReason)

	timestampFile := filepath.Join(tempDir, "ragequit-timestamp.txt")
	assert.True(t, system.FileExists(timestampFile))

	content := system.ReadFile(timestampFile)
	assert.Contains(t, content, "Ragequit executed at:")
	assert.Contains(t, content, testReason)
	assert.Contains(t, content, "Triggered by:")
}

func TestGenerateRecoveryPlan(t *testing.T) {
	tempDir := t.TempDir()
	originalHome := os.Getenv("HOME")
	defer func() {
		if originalHome != "" {
			_ = os.Setenv("HOME", originalHome)
		} else {
			_ = os.Unsetenv("HOME")
		}
	}()
	_ = os.Setenv("HOME", tempDir)

	rc := eos_io.NewContext(context.Background(), "test")

	recovery.GenerateRecoveryPlan(rc)

	recoveryFile := filepath.Join(tempDir, "RAGEQUIT-RECOVERY-PLAN.md")
	assert.True(t, system.FileExists(recoveryFile))

	content := system.ReadFile(recoveryFile)
	assert.Contains(t, content, "# RAGEQUIT RECOVERY PLAN")
	assert.Contains(t, content, "## IMMEDIATE ACTIONS AFTER REBOOT")
	assert.Contains(t, content, "## SERVICE RECOVERY")
}

func TestEnvironmentDetection(t *testing.T) {
	tempDir := t.TempDir()
	originalHome := os.Getenv("HOME")
	defer func() {
		if originalHome != "" {
			_ = os.Setenv("HOME", originalHome)
		} else {
			_ = os.Unsetenv("HOME")
		}
	}()
	_ = os.Setenv("HOME", tempDir)

	rc := eos_io.NewContext(context.Background(), "test")

	diagnostics.DetectEnvironment(rc)

	envFile := filepath.Join(tempDir, "ragequit-environment.txt")
	assert.True(t, system.FileExists(envFile))

	content := system.ReadFile(envFile)
	assert.Contains(t, content, "=== Environment Detection ===")
	assert.Contains(t, content, "Environment:")
	// Init detection is optional since it depends on system state
	// Just verify the file was created with basic content
}