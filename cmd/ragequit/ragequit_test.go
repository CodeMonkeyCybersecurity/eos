package ragequit

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
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
		hostname := getHostname()
		assert.NotEmpty(t, hostname)
		assert.NotEqual(t, "unknown", hostname)
	})

	t.Run("getHomeDir", func(t *testing.T) {
		homeDir := getHomeDir()
		assert.NotEmpty(t, homeDir)
	})

	t.Run("fileExists", func(t *testing.T) {
		// Test with existing file
		tempFile := filepath.Join(t.TempDir(), "test-file")
		err := os.WriteFile(tempFile, []byte("test"), 0644)
		require.NoError(t, err)
		
		assert.True(t, fileExists(tempFile))
		assert.False(t, fileExists("/nonexistent/file"))
	})

	t.Run("dirExists", func(t *testing.T) {
		tempDir := t.TempDir()
		assert.True(t, dirExists(tempDir))
		assert.False(t, dirExists("/nonexistent/directory"))
	})

	t.Run("commandExists", func(t *testing.T) {
		// Test with a command that should exist on most systems
		assert.True(t, commandExists("echo"))
		assert.False(t, commandExists("nonexistent-command-12345"))
	})

	t.Run("readFile", func(t *testing.T) {
		tempFile := filepath.Join(t.TempDir(), "test-content")
		testContent := "test file content"
		err := os.WriteFile(tempFile, []byte(testContent), 0644)
		require.NoError(t, err)

		content := readFile(tempFile)
		assert.Equal(t, testContent, content)

		// Test with nonexistent file
		emptyContent := readFile("/nonexistent/file")
		assert.Empty(t, emptyContent)
	})

	t.Run("runCommandWithTimeout", func(t *testing.T) {
		// Test successful command
		output := runCommandWithTimeout("echo", []string{"hello", "world"}, 5*time.Second)
		assert.Contains(t, output, "hello world")

		// Test command timeout
		output = runCommandWithTimeout("sleep", []string{"10"}, 100*time.Millisecond)
		assert.Empty(t, output)

		// Test nonexistent command
		output = runCommandWithTimeout("nonexistent-command", []string{}, 5*time.Second)
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
	createTimestampFile(rc, testReason)

	timestampFile := filepath.Join(tempDir, "ragequit-timestamp.txt")
	assert.True(t, fileExists(timestampFile))

	content := readFile(timestampFile)
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

	reason = "test recovery plan"
	generateRecoveryPlan(rc)

	recoveryFile := filepath.Join(tempDir, "investigate-ragequit.md")
	assert.True(t, fileExists(recoveryFile))

	content := readFile(recoveryFile)
	assert.Contains(t, content, "# Ragequit Investigation Checklist")
	assert.Contains(t, content, "## Investigation Steps")
	assert.Contains(t, content, "## Recovery Commands")
	assert.Contains(t, content, reason)
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

	detectEnvironment(rc)

	envFile := filepath.Join(tempDir, "ragequit-environment.txt")
	assert.True(t, fileExists(envFile))

	content := readFile(envFile)
	assert.Contains(t, content, "=== Environment Detection ===")
	assert.Contains(t, content, "Environment:")
	// Init detection is optional since it depends on system state
	// Just verify the file was created with basic content
}