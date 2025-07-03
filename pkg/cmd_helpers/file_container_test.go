package cmd_helpers_test

import (
	"context"
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/cmd_helpers"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewFileServiceContainer(t *testing.T) {
	ctx := context.Background()
	rc := &eos_io.RuntimeContext{
		Ctx: ctx,
	}

	container, err := cmd_helpers.NewFileServiceContainer(rc)
	require.NoError(t, err)
	assert.NotNil(t, container)
	assert.NotNil(t, container.Service)
}

func TestFileServiceContainer_FileExists(t *testing.T) {
	ctx := context.Background()
	rc := &eos_io.RuntimeContext{
		Ctx: ctx,
	}

	container, err := cmd_helpers.NewFileServiceContainer(rc)
	require.NoError(t, err)

	// Test with a file that should exist
	exists := container.FileExists("/etc/hosts")
	assert.True(t, exists)

	// Test with a file that shouldn't exist
	exists = container.FileExists("/nonexistent/file/path")
	assert.False(t, exists)
}

func TestFileServiceContainer_CopyFile(t *testing.T) {
	ctx := context.Background()
	rc := &eos_io.RuntimeContext{
		Ctx: ctx,
	}

	container, err := cmd_helpers.NewFileServiceContainer(rc)
	require.NoError(t, err)

	// Create a temporary directory for testing
	tmpDir := t.TempDir()
	srcFile := tmpDir + "/source.txt"
	dstFile := tmpDir + "/dest.txt"

	// Create source file
	err = container.Service.WriteFile(ctx, srcFile, []byte("test content"), 0644)
	require.NoError(t, err)

	// Copy file
	err = container.CopyFile(srcFile, dstFile)
	assert.NoError(t, err)

	// Verify destination exists
	exists := container.FileExists(dstFile)
	assert.True(t, exists)
}

func TestFileServiceContainer_CopyFileWithBackup(t *testing.T) {
	ctx := context.Background()
	rc := &eos_io.RuntimeContext{
		Ctx: ctx,
	}

	container, err := cmd_helpers.NewFileServiceContainer(rc)
	require.NoError(t, err)

	// Create a temporary directory for testing
	tmpDir := t.TempDir()
	srcFile := tmpDir + "/source.txt"
	dstFile := tmpDir + "/dest.txt"

	// Create source file
	err = container.Service.WriteFile(ctx, srcFile, []byte("new content"), 0644)
	require.NoError(t, err)

	// Create existing destination file
	err = container.Service.WriteFile(ctx, dstFile, []byte("old content"), 0644)
	require.NoError(t, err)

	// Copy with backup
	err = container.CopyFileWithBackup(srcFile, dstFile)
	assert.NoError(t, err)

	// Verify destination has new content
	data, err := container.Service.ReadFile(ctx, dstFile)
	require.NoError(t, err)
	assert.Equal(t, "new content", string(data))

	// Verify backup was created
	backupFile := dstFile + ".bak"
	exists := container.FileExists(backupFile)
	assert.True(t, exists)

	// Verify backup has old content
	backupData, err := container.Service.ReadFile(ctx, backupFile)
	require.NoError(t, err)
	assert.Equal(t, "old content", string(backupData))
}