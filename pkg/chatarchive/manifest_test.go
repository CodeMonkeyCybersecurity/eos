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

func TestReadManifest_ReadError(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	m, err := ReadManifest(dir)
	assert.Error(t, err)
	assert.Nil(t, m)
	assert.Contains(t, err.Error(), "read manifest")
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
	assert.Contains(t, err.Error(), "manifest")
}

func TestWriteManifest_ReplaceFailure(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	m := &Manifest{GeneratedAt: "2026-01-01T00:00:00Z"}

	err := WriteManifest(dir, m)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "replace manifest")
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

func TestRecoverManifest(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "manifest.json")
	require.NoError(t, os.WriteFile(path, []byte("{bad json"), 0644))

	recovered, err := RecoverManifest(path)
	require.NoError(t, err)
	assert.FileExists(t, recovered)
	_, statErr := os.Stat(path)
	assert.True(t, os.IsNotExist(statErr))
}

func TestRecoverManifest_MissingFile(t *testing.T) {
	t.Parallel()

	recovered, err := RecoverManifest(filepath.Join(t.TempDir(), "missing.json"))
	assert.Error(t, err)
	assert.Empty(t, recovered)
}

func TestMergeEntries_DoesNotMutateInput(t *testing.T) {
	t.Parallel()

	existing := &Manifest{
		GeneratedAt: "2025-01-01T00:00:00Z",
		Sources:     []string{"/src"},
		DestDir:     "/dest",
		Entries: []Entry{
			{SHA256: "hash1", SourcePath: "/src/a.jsonl", Copied: true},
		},
	}
	originalTimestamp := existing.GeneratedAt
	originalEntryCount := len(existing.Entries)

	newEntries := []Entry{
		{SHA256: "hash2", SourcePath: "/src/b.jsonl", Copied: true},
	}

	merged := MergeEntries(existing, newEntries)

	// Merged should have 2 entries
	assert.Len(t, merged.Entries, 2)

	// Original must not be mutated
	assert.Equal(t, originalTimestamp, existing.GeneratedAt, "input timestamp must not be mutated")
	assert.Len(t, existing.Entries, originalEntryCount, "input entries must not be mutated")

	// Merged must be a different pointer
	assert.NotSame(t, existing, merged, "MergeEntries must return a new Manifest, not the input")
}

func TestManifestVersion(t *testing.T) {
	t.Parallel()

	t.Run("MergeEntries sets version on new manifest", func(t *testing.T) {
		t.Parallel()
		merged := MergeEntries(nil, []Entry{{SHA256: "abc", Copied: true}})
		assert.Equal(t, ManifestVersion, merged.Version)
	})

	t.Run("MergeEntries sets version on existing manifest", func(t *testing.T) {
		t.Parallel()
		existing := &Manifest{Version: 0, Entries: []Entry{}}
		merged := MergeEntries(existing, []Entry{{SHA256: "abc", Copied: true}})
		assert.Equal(t, ManifestVersion, merged.Version, "should upgrade version")
	})

	t.Run("WriteManifest includes version in JSON", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		path := filepath.Join(dir, "manifest.json")
		m := &Manifest{Version: ManifestVersion, GeneratedAt: "2026-03-19T00:00:00Z"}
		require.NoError(t, WriteManifest(path, m))

		data, err := os.ReadFile(path)
		require.NoError(t, err)
		assert.Contains(t, string(data), `"version": 1`)
	})

	t.Run("ReadManifest reads version from disk", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		path := filepath.Join(dir, "manifest.json")
		require.NoError(t, WriteManifest(path, &Manifest{
			Version:     ManifestVersion,
			GeneratedAt: "2026-03-19T00:00:00Z",
		}))
		m, err := ReadManifest(path)
		require.NoError(t, err)
		assert.Equal(t, ManifestVersion, m.Version)
	})
}

func TestExistingHashes_SkipsEmptyHash(t *testing.T) {
	t.Parallel()
	m := &Manifest{
		Entries: []Entry{
			{SHA256: "", DestPath: "/dest/empty.jsonl", Copied: true},
			{SHA256: "validhash", DestPath: "/dest/real.jsonl", Copied: true},
		},
	}
	hashes := ExistingHashes(m)
	assert.Len(t, hashes, 1)
	assert.Equal(t, "/dest/real.jsonl", hashes["validhash"])
}
