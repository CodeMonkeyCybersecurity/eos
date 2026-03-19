package chatarchive

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestManifestPath(t *testing.T) {
	t.Parallel()
	got := filepath.ToSlash(ManifestPath("/some/dir"))
	assert.Equal(t, "/some/dir/manifest.json", got)
}

func TestReadManifest_NotFound(t *testing.T) {
	t.Parallel()
	m, err := ReadManifest("/nonexistent/manifest.json")
	assert.NoError(t, err, "missing file should not be an error")
	assert.Nil(t, m)
}

func TestReadManifest_InvalidJSON(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "manifest.json")
	require.NoError(t, os.WriteFile(path, []byte("{invalid"), 0644))

	m, err := ReadManifest(path)
	assert.Error(t, err)
	assert.Nil(t, m)
	assert.Contains(t, err.Error(), "parse manifest")
}

func TestWriteAndReadManifest_RoundTrip(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "manifest.json")

	original := &Manifest{
		GeneratedAt: "2026-03-19T00:00:00Z",
		Sources:     []string{"/home/user/Dev"},
		DestDir:     "/home/user/archive",
		Entries: []Entry{
			{
				SourcePath:   "/home/user/Dev/chat.jsonl",
				DestPath:     "/home/user/archive/abc123-chat.jsonl",
				SHA256:       "abc123def456",
				SizeBytes:    1024,
				Copied:       true,
				Conversation: "chat",
			},
		},
	}

	require.NoError(t, WriteManifest(path, original))

	loaded, err := ReadManifest(path)
	require.NoError(t, err)
	require.NotNil(t, loaded)
	assert.Equal(t, original.GeneratedAt, loaded.GeneratedAt)
	assert.Equal(t, original.Sources, loaded.Sources)
	assert.Equal(t, original.DestDir, loaded.DestDir)
	assert.Len(t, loaded.Entries, 1)
	assert.Equal(t, original.Entries[0].SHA256, loaded.Entries[0].SHA256)
}

func TestWriteManifest_ValidJSON(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "manifest.json")

	m := &Manifest{
		GeneratedAt: "2026-03-19T00:00:00Z",
		Entries:     []Entry{},
	}
	require.NoError(t, WriteManifest(path, m))

	// Verify it's valid JSON
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.True(t, json.Valid(data), "manifest should be valid JSON")
}

func TestExistingHashes_NilManifest(t *testing.T) {
	t.Parallel()
	hashes := ExistingHashes(nil)
	assert.Empty(t, hashes)
	assert.NotNil(t, hashes, "should return empty map, not nil")
}

func TestExistingHashes_WithEntries(t *testing.T) {
	t.Parallel()
	m := &Manifest{
		Entries: []Entry{
			{SHA256: "hash1", DestPath: "/dest/file1.jsonl", Copied: true},
			{SHA256: "hash2", DestPath: "/dest/file2.jsonl", Copied: true},
			{SHA256: "hash3", DestPath: "/dest/dup.jsonl", Copied: false, DuplicateOf: "/dest/file1.jsonl"},
		},
	}

	hashes := ExistingHashes(m)
	assert.Len(t, hashes, 2, "should only include copied entries")
	assert.Equal(t, "/dest/file1.jsonl", hashes["hash1"])
	assert.Equal(t, "/dest/file2.jsonl", hashes["hash2"])
}

func TestMergeEntries_NilExisting(t *testing.T) {
	t.Parallel()
	newEntries := []Entry{
		{SHA256: "abc", SourcePath: "/src/a.jsonl", Copied: true},
	}

	merged := MergeEntries(nil, newEntries)
	assert.NotNil(t, merged)
	assert.Len(t, merged.Entries, 1)
	assert.NotEmpty(t, merged.GeneratedAt)
}

func TestMergeEntries_NoDuplicates(t *testing.T) {
	t.Parallel()
	existing := &Manifest{
		GeneratedAt: "2026-01-01T00:00:00Z",
		Entries: []Entry{
			{SHA256: "hash1", SourcePath: "/src/a.jsonl", Copied: true},
		},
	}
	newEntries := []Entry{
		{SHA256: "hash2", SourcePath: "/src/b.jsonl", Copied: true},
	}

	merged := MergeEntries(existing, newEntries)
	assert.Len(t, merged.Entries, 2, "should contain both old and new entries")
}

func TestMergeEntries_SkipsDuplicateHashes(t *testing.T) {
	t.Parallel()
	existing := &Manifest{
		GeneratedAt: "2026-01-01T00:00:00Z",
		Entries: []Entry{
			{SHA256: "hash1", SourcePath: "/src/a.jsonl", Copied: true},
		},
	}
	newEntries := []Entry{
		{SHA256: "hash1", SourcePath: "/src/same-content.jsonl", Copied: true},
		{SHA256: "hash2", SourcePath: "/src/b.jsonl", Copied: true},
	}

	merged := MergeEntries(existing, newEntries)
	assert.Len(t, merged.Entries, 2, "should not duplicate hash1")
}

func TestWriteManifest_InvalidPath(t *testing.T) {
	t.Parallel()
	m := &Manifest{GeneratedAt: "2026-01-01T00:00:00Z"}
	err := WriteManifest("/nonexistent/dir/manifest.json", m)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "write manifest")
}

func TestMergeEntries_UpdatesTimestamp(t *testing.T) {
	t.Parallel()
	existing := &Manifest{
		GeneratedAt: "2025-01-01T00:00:00Z",
		Entries:     []Entry{},
	}

	merged := MergeEntries(existing, []Entry{})
	assert.NotEqual(t, "2025-01-01T00:00:00Z", merged.GeneratedAt,
		"should update GeneratedAt timestamp")
}
