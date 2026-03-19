//go:build integration

package chatarchive

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestArchive_Integration_FullFlow(t *testing.T) {
	t.Parallel()
	rc := testutil.TestRuntimeContext(t)

	// Setup: create source files
	srcDir := t.TempDir()
	destDir := filepath.Join(t.TempDir(), "archive")

	sessionsDir := filepath.Join(srcDir, "sessions")
	require.NoError(t, os.MkdirAll(sessionsDir, 0755))

	// Create unique transcript files
	require.NoError(t, os.WriteFile(
		filepath.Join(sessionsDir, "chat-session-1.jsonl"),
		[]byte(`{"role":"user","content":"hello"}`), 0644))
	require.NoError(t, os.WriteFile(
		filepath.Join(sessionsDir, "chat-session-2.jsonl"),
		[]byte(`{"role":"assistant","content":"hi there"}`), 0644))

	// Create a duplicate (same content as session-1)
	require.NoError(t, os.WriteFile(
		filepath.Join(sessionsDir, "chat-session-1-copy.jsonl"),
		[]byte(`{"role":"user","content":"hello"}`), 0644))

	// Create memory.md
	require.NoError(t, os.WriteFile(
		filepath.Join(srcDir, "memory.md"),
		[]byte("# Agent Memory"), 0644))

	// Run archive
	result, err := Archive(rc, Options{
		Sources: []string{srcDir},
		Dest:    destDir,
		DryRun:  false,
	})
	require.NoError(t, err)

	// Verify results
	assert.Equal(t, 3, result.UniqueFiles, "should copy 3 unique files (2 chats + memory.md)")
	assert.Equal(t, 1, result.Duplicates, "should detect 1 duplicate")
	assert.NotEmpty(t, result.ManifestPath)

	// Verify manifest is valid JSON on disk
	data, err := os.ReadFile(result.ManifestPath)
	require.NoError(t, err)
	assert.True(t, json.Valid(data))

	var manifest Manifest
	require.NoError(t, json.Unmarshal(data, &manifest))
	assert.Len(t, manifest.Entries, 4, "manifest should have 4 entries (3 unique + 1 dup)")
}

func TestArchive_Integration_Idempotent(t *testing.T) {
	t.Parallel()
	rc := testutil.TestRuntimeContext(t)

	srcDir := t.TempDir()
	destDir := filepath.Join(t.TempDir(), "archive")

	sessionsDir := filepath.Join(srcDir, "sessions")
	require.NoError(t, os.MkdirAll(sessionsDir, 0755))
	require.NoError(t, os.WriteFile(
		filepath.Join(sessionsDir, "chat.jsonl"),
		[]byte(`{"role":"user","content":"test"}`), 0644))

	// First run
	result1, err := Archive(rc, Options{
		Sources: []string{srcDir},
		Dest:    destDir,
	})
	require.NoError(t, err)
	assert.Equal(t, 1, result1.UniqueFiles)

	// Second run (same content) — should be idempotent
	result2, err := Archive(rc, Options{
		Sources: []string{srcDir},
		Dest:    destDir,
	})
	require.NoError(t, err)
	assert.Equal(t, 0, result2.UniqueFiles, "second run should copy 0 new files")
	assert.Equal(t, 1, result2.Duplicates, "second run should detect 1 duplicate")

	// Manifest should not grow unboundedly — MergeEntries skips
	// entries whose hash already exists in the manifest.
	m, err := ReadManifest(ManifestPath(destDir))
	require.NoError(t, err)
	assert.Len(t, m.Entries, 1, "manifest should still have 1 entry (duplicate skipped by merge)")
}

func TestArchive_Integration_DryRun(t *testing.T) {
	t.Parallel()
	rc := testutil.TestRuntimeContext(t)

	srcDir := t.TempDir()
	destDir := filepath.Join(t.TempDir(), "archive")

	sessionsDir := filepath.Join(srcDir, "sessions")
	require.NoError(t, os.MkdirAll(sessionsDir, 0755))
	require.NoError(t, os.WriteFile(
		filepath.Join(sessionsDir, "chat.jsonl"),
		[]byte(`{"role":"user","content":"dry-run-test"}`), 0644))

	result, err := Archive(rc, Options{
		Sources: []string{srcDir},
		Dest:    destDir,
		DryRun:  true,
	})
	require.NoError(t, err)
	assert.Equal(t, 1, result.UniqueFiles)
	assert.Empty(t, result.ManifestPath, "dry run should not write manifest")

	// Verify no files were created
	_, err = os.Stat(destDir)
	assert.True(t, os.IsNotExist(err), "dry run should not create dest directory")
}

func TestArchive_Integration_EmptySources(t *testing.T) {
	t.Parallel()
	rc := testutil.TestRuntimeContext(t)

	destDir := filepath.Join(t.TempDir(), "archive")

	result, err := Archive(rc, Options{
		Sources: []string{},
		Dest:    destDir,
	})
	require.NoError(t, err)
	assert.Equal(t, 0, result.UniqueFiles)
	assert.Equal(t, 0, result.Duplicates)
}

func TestArchive_Integration_CopyError(t *testing.T) {
	t.Parallel()
	rc := testutil.TestRuntimeContext(t)

	srcDir := t.TempDir()
	// Create dest dir as a file (not directory) to force copy error
	destDir := filepath.Join(t.TempDir(), "archive")
	require.NoError(t, os.MkdirAll(destDir, 0755))

	sessionsDir := filepath.Join(srcDir, "sessions")
	require.NoError(t, os.MkdirAll(sessionsDir, 0755))
	chatFile := filepath.Join(sessionsDir, "chat.jsonl")
	require.NoError(t, os.WriteFile(chatFile, []byte(`{"role":"user"}`), 0644))

	// Make dest dir read-only so file creation fails
	require.NoError(t, os.Chmod(destDir, 0555))
	defer func() { _ = os.Chmod(destDir, 0755) }() // restore for cleanup

	_, err := Archive(rc, Options{
		Sources: []string{srcDir},
		Dest:    destDir,
	})
	assert.Error(t, err, "should fail when dest dir is read-only")
}

func TestArchive_Integration_SkipsEmptyFiles(t *testing.T) {
	t.Parallel()
	rc := testutil.TestRuntimeContext(t)

	srcDir := t.TempDir()
	destDir := filepath.Join(t.TempDir(), "archive")

	sessionsDir := filepath.Join(srcDir, "sessions")
	require.NoError(t, os.MkdirAll(sessionsDir, 0755))
	// Empty file
	require.NoError(t, os.WriteFile(filepath.Join(sessionsDir, "empty-chat.jsonl"), []byte{}, 0644))
	// Non-empty file
	require.NoError(t, os.WriteFile(filepath.Join(sessionsDir, "real-chat.jsonl"), []byte("data"), 0644))

	result, err := Archive(rc, Options{
		Sources: []string{srcDir},
		Dest:    destDir,
	})
	require.NoError(t, err)
	assert.Equal(t, 1, result.UniqueFiles, "should only copy non-empty file")
}
