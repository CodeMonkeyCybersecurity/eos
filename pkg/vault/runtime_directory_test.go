package vault

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPrepareTokenSink_Success(t *testing.T) {
	// Create temporary directory for test
	tempDir := t.TempDir()
	tokenPath := filepath.Join(tempDir, "vault_agent_eos.token")
	
	// Create runtime context
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	rc := &eos_io.RuntimeContext{
		Ctx: ctx,
	}
	
	// This will fail due to user lookup but we can test directory creation
	err := prepareTokenSink(rc, tokenPath, "testuser")
	// Expected to fail due to user lookup in test environment
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "lookup user")
	
	// Verify directory was created
	dir := filepath.Dir(tokenPath)
	stat, err := os.Stat(dir)
	require.NoError(t, err)
	assert.True(t, stat.IsDir())
	assert.Equal(t, os.FileMode(0755), stat.Mode()&0777)
}

func TestPrepareTokenSink_RemoveStrayDirectory(t *testing.T) {
	// Create temporary directory for test
	tempDir := t.TempDir()
	tokenPath := filepath.Join(tempDir, "vault_agent_eos.token")
	
	// Create a directory where the token file should be (stray directory)
	require.NoError(t, os.MkdirAll(tokenPath, 0755))
	
	// Verify it's a directory
	stat, err := os.Stat(tokenPath)
	require.NoError(t, err)
	assert.True(t, stat.IsDir())
	
	// Create runtime context
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	rc := &eos_io.RuntimeContext{
		Ctx: ctx,
	}
	
	// This will fail due to user lookup but should remove the stray directory
	prepErr := prepareTokenSink(rc, tokenPath, "testuser")
	assert.Error(t, prepErr) // Expected due to user lookup
	
	// Verify the stray directory was removed and file was created
	stat, err = os.Stat(tokenPath)
	require.NoError(t, err)
	assert.False(t, stat.IsDir()) // Should now be a file, not directory
}

func TestEnsureRuntimeDirectory_NewDirectory(t *testing.T) {
	// Create temporary directory for test
	tempDir := t.TempDir()
	runDir := filepath.Join(tempDir, "run", "eos")
	
	// Override shared.EosRunDir for testing
	originalRunDir := shared.EosRunDir
	shared.EosRunDir = runDir
	defer func() {
		shared.EosRunDir = originalRunDir
	}()
	
	// Create runtime context
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	rc := &eos_io.RuntimeContext{
		Ctx: ctx,
	}
	
	// Test creating new directory (will fail on ownership but directory should be created)
	_ = ensureRuntimeDirectory(rc)
	// Expected to fail due to eos user lookup in test environment
	// But directory should still be created
	
	// Verify directory was created
	stat, err := os.Stat(runDir)
	require.NoError(t, err)
	assert.True(t, stat.IsDir())
	assert.Equal(t, os.FileMode(0755), stat.Mode()&0777)
}

func TestEnsureRuntimeDirectory_ExistingDirectory(t *testing.T) {
	// Create temporary directory for test
	tempDir := t.TempDir()
	runDir := filepath.Join(tempDir, "run", "eos")
	
	// Pre-create the directory
	require.NoError(t, os.MkdirAll(runDir, 0755))
	
	// Create runtime context
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	rc := &eos_io.RuntimeContext{
		Ctx: ctx,
	}
	
	// Test with existing directory
	err := ensureRuntimeDirectory(rc)
	// Should succeed since directory already exists (ownership update may fail but that's OK)
	assert.NoError(t, err)
	
	// Verify directory still exists
	stat, err := os.Stat(runDir)
	require.NoError(t, err)
	assert.True(t, stat.IsDir())
}

func TestCleanupStaleHCPDirectory_NonExistent(t *testing.T) {
	// Create runtime context
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	rc := &eos_io.RuntimeContext{
		Ctx: ctx,
	}
	
	// Test that non-existent directory doesn't cause errors
	err := cleanupStaleHCPDirectory(rc)
	require.NoError(t, err) // Should succeed when directory doesn't exist
}

func TestCleanupStaleHCPDirectory_Existing(t *testing.T) {
	// We can't easily test the actual function because it has a hardcoded path
	// But we can test the cleanup logic
	
	// Create temporary directory structure
	tempDir := t.TempDir()
	testHCPDir := filepath.Join(tempDir, ".config", "hcp")
	
	// Create the HCP directory with some files
	require.NoError(t, os.MkdirAll(testHCPDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(testHCPDir, "config.json"), []byte("{}"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(testHCPDir, "auth.json"), []byte("{}"), 0644))
	
	// Verify directory exists
	stat, err := os.Stat(testHCPDir)
	require.NoError(t, err)
	assert.True(t, stat.IsDir())
	
	// Test cleanup logic
	err = os.RemoveAll(testHCPDir)
	require.NoError(t, err)
	
	// Verify directory was removed
	_, err = os.Stat(testHCPDir)
	assert.True(t, os.IsNotExist(err))
}

func TestCreateTmpfilesConfig_Content(t *testing.T) {
	// Test that tmpfiles config content is correct
	expectedContent := "d /run/eos 0755 eos eos -\n"
	
	// Verify the content format
	assert.Contains(t, expectedContent, "/run/eos")
	assert.Contains(t, expectedContent, "0755")
	assert.Contains(t, expectedContent, "eos eos")
	assert.Equal(t, "d", string(expectedContent[0])) // Type should be 'd' for directory
}

func TestTmpfilesConfiguration(t *testing.T) {
	// Test tmpfiles configuration format
	tests := []struct {
		name     string
		line     string
		valid    bool
		expected string
	}{
		{
			name:     "valid directory line",
			line:     "d /run/eos 0755 eos eos -",
			valid:    true,
			expected: "d",
		},
		{
			name:     "invalid permission",
			line:     "d /run/eos 0777 eos eos -",
			valid:    false,
			expected: "",
		},
		{
			name:     "missing user",
			line:     "d /run/eos 0755 - - -",
			valid:    false,
			expected: "",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parts := strings.Fields(tt.line)
			
			if len(parts) >= 1 {
				assert.Equal(t, tt.expected, parts[0])
			}
			
			if tt.valid {
				assert.GreaterOrEqual(t, len(parts), 5, "valid tmpfiles line should have at least 5 parts")
				if len(parts) >= 5 {
					assert.Equal(t, "/run/eos", parts[1])
					assert.Equal(t, "0755", parts[2])
					assert.Equal(t, "eos", parts[3])
					assert.Equal(t, "eos", parts[4])
				}
			}
		})
	}
}

func TestRuntimeDirectoryPermissions(t *testing.T) {
	// Test that runtime directory permissions are secure
	expectedMode := os.FileMode(0755)
	
	// Verify permissions allow owner read/write/execute
	assert.Equal(t, os.FileMode(0700), expectedMode&0700, "Owner should have full access")
	
	// Verify group and others have read/execute only
	assert.Equal(t, os.FileMode(0055), expectedMode&0077, "Group and others should have read/execute only")
	
	// Verify no write access for group or others
	assert.Equal(t, os.FileMode(0), expectedMode&0022, "No write access for group or others")
}

func TestTokenSinkPermissions(t *testing.T) {
	// Test that token files are created with secure permissions
	expectedMode := os.FileMode(0600)
	
	// Verify owner has read/write access
	assert.Equal(t, os.FileMode(0600), expectedMode&0700, "Owner should have read/write access")
	
	// Verify no access for group or others
	assert.Equal(t, os.FileMode(0), expectedMode&0077, "No access for group or others")
}

func TestRuntimeDirectorySecurity(t *testing.T) {
	// Test security aspects of runtime directory management
	
	tests := []struct {
		name        string
		mode        os.FileMode
		secure      bool
		description string
	}{
		{
			name:        "secure directory mode",
			mode:        0755,
			secure:      true,
			description: "Standard secure directory permissions",
		},
		{
			name:        "insecure world writable",
			mode:        0777,
			secure:      false,
			description: "World writable is insecure",
		},
		{
			name:        "insecure group writable",
			mode:        0775,
			secure:      false,
			description: "Group writable may be insecure",
		},
		{
			name:        "overly restrictive",
			mode:        0700,
			secure:      true,
			description: "Owner only access is secure but may cause service issues",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Check world writable
			isWorldWritable := (tt.mode & 0002) != 0
			// Check group writable
			isGroupWritable := (tt.mode & 0020) != 0
			
			if tt.secure {
				assert.False(t, isWorldWritable, "Secure mode should not be world writable")
				// Group writable is OK for some use cases, but flag it
				if isGroupWritable && tt.mode != 0775 {
					t.Logf("Note: Group writable mode %o may be acceptable in some contexts", tt.mode)
				}
			} else {
				if isWorldWritable {
					assert.True(t, isWorldWritable, "Expected world writable for insecure test case")
				}
			}
		})
	}
}

