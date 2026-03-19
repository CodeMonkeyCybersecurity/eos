package chatarchive

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResultAddFailureCapsDetails(t *testing.T) {
	t.Parallel()

	result := &Result{}
	for i := 0; i < 25; i++ {
		result.addFailure("path", "hash", assert.AnError)
	}

	assert.Equal(t, 25, result.FailureCount)
	assert.Len(t, result.Failures, 20)
}

func TestCopyFile_Success(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	src := filepath.Join(dir, "src.jsonl")
	dst := filepath.Join(dir, "nested", "dst.jsonl")
	require.NoError(t, os.WriteFile(src, []byte("hello"), 0640))

	require.NoError(t, copyFile(src, dst))

	data, err := os.ReadFile(dst)
	require.NoError(t, err)
	assert.Equal(t, "hello", string(data))

	info, err := os.Stat(dst)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0640), info.Mode().Perm())
}

func TestCopyFile_MissingSource(t *testing.T) {
	t.Parallel()

	err := copyFile("/does/not/exist", filepath.Join(t.TempDir(), "dst"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "open source")
}

func TestCopyFile_InvalidDestinationParent(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	src := filepath.Join(dir, "src.jsonl")
	parentFile := filepath.Join(dir, "parent")
	require.NoError(t, os.WriteFile(src, []byte("hello"), 0644))
	require.NoError(t, os.WriteFile(parentFile, []byte("block"), 0644))

	err := copyFile(src, filepath.Join(parentFile, "dst.jsonl"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "create destination dir")
}

func TestCopyFile_RenameFailure(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	src := filepath.Join(dir, "src.jsonl")
	dstDir := filepath.Join(dir, "dst")
	require.NoError(t, os.WriteFile(src, []byte("hello"), 0644))
	require.NoError(t, os.MkdirAll(dstDir, 0755))

	err := copyFile(src, dstDir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "replace destination")
}
