package chatarchive

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFileSHA256(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		content  string
		wantHash string
		wantSize int64
	}{
		{
			name:     "known content",
			content:  "hello world\n",
			wantHash: "a948904f2f0f479b8f8197694b30184b0d2ed1c1cd2a1ec0fb85d299a192a447",
			wantSize: 12,
		},
		{
			name:     "empty file",
			content:  "",
			wantHash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			wantSize: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			path := filepath.Join(dir, "testfile")
			require.NoError(t, os.WriteFile(path, []byte(tt.content), 0644))

			hash, size, err := FileSHA256(path)
			require.NoError(t, err)
			assert.Equal(t, tt.wantSize, size)
			assert.Equal(t, tt.wantHash, hash, "SHA-256 hash mismatch for %q", tt.name)
		})
	}
}

func TestFileSHA256_NonexistentFile(t *testing.T) {
	t.Parallel()
	_, _, err := FileSHA256("/nonexistent/path/file.txt")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "open file for hashing")
}

func TestFileSHA256_Deterministic(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	content := "reproducible content for determinism test"

	// Write same content to two files
	path1 := filepath.Join(dir, "file1")
	path2 := filepath.Join(dir, "file2")
	require.NoError(t, os.WriteFile(path1, []byte(content), 0644))
	require.NoError(t, os.WriteFile(path2, []byte(content), 0644))

	hash1, size1, err := FileSHA256(path1)
	require.NoError(t, err)
	hash2, size2, err := FileSHA256(path2)
	require.NoError(t, err)

	assert.Equal(t, hash1, hash2, "same content should produce same hash")
	assert.Equal(t, size1, size2, "same content should produce same size")
}

func TestFileSHA256_DifferentContent(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	path1 := filepath.Join(dir, "file1")
	path2 := filepath.Join(dir, "file2")
	require.NoError(t, os.WriteFile(path1, []byte("content A"), 0644))
	require.NoError(t, os.WriteFile(path2, []byte("content B"), 0644))

	hash1, _, err := FileSHA256(path1)
	require.NoError(t, err)
	hash2, _, err := FileSHA256(path2)
	require.NoError(t, err)

	assert.NotEqual(t, hash1, hash2, "different content should produce different hashes")
}
