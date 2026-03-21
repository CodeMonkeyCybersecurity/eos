//go:build integration

package chatarchive

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
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
	assert.Len(t, manifest.Entries, 4, "manifest should include unique and duplicate rows from the initial run")
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
	assert.Equal(t, 0, result2.Duplicates, "second run should not count manifest hits as in-run duplicates")
	assert.Equal(t, 1, result2.Skipped, "second run should count existing manifest entries as skipped")

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
	missingSource := filepath.Join(t.TempDir(), "missing")

	result, err := Archive(rc, Options{
		Sources: []string{missingSource},
		Dest:    destDir,
	})
	require.NoError(t, err)
	assert.Equal(t, 0, result.UniqueFiles)
	assert.Equal(t, 0, result.Duplicates)
	assert.Equal(t, 0, result.Skipped)
}

func TestArchive_Integration_CopyError(t *testing.T) {
	t.Parallel()
	rc := testutil.TestRuntimeContext(t)

	srcDir := t.TempDir()
	destDir := filepath.Join(t.TempDir(), "archive")
	require.NoError(t, os.WriteFile(destDir, []byte("not-a-directory"), 0644))

	sessionsDir := filepath.Join(srcDir, "sessions")
	require.NoError(t, os.MkdirAll(sessionsDir, 0755))
	chatFile := filepath.Join(sessionsDir, "chat.jsonl")
	require.NoError(t, os.WriteFile(chatFile, []byte(`{"role":"user"}`), 0644))

	_, err := Archive(rc, Options{
		Sources: []string{srcDir},
		Dest:    destDir,
	})
	assert.Error(t, err, "should fail when destination path is not a directory")
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
	assert.Equal(t, 1, result.EmptyFiles, "should report empty candidate files")
}

func TestArchive_Integration_RecoversCorruptManifest(t *testing.T) {
	t.Parallel()
	rc := testutil.TestRuntimeContext(t)

	srcDir := t.TempDir()
	destDir := filepath.Join(t.TempDir(), "archive")

	sessionsDir := filepath.Join(srcDir, "sessions")
	require.NoError(t, os.MkdirAll(sessionsDir, 0755))
	require.NoError(t, os.WriteFile(
		filepath.Join(sessionsDir, "chat.jsonl"),
		[]byte(`{"role":"user","content":"recover"}`), 0644))

	require.NoError(t, os.MkdirAll(destDir, 0755))
	require.NoError(t, os.WriteFile(ManifestPath(destDir), []byte("{not json"), 0644))

	result, err := Archive(rc, Options{
		Sources: []string{srcDir},
		Dest:    destDir,
	})
	require.NoError(t, err)
	assert.Equal(t, 1, result.UniqueFiles)
	assert.NotEmpty(t, result.RecoveredManifestPath)
	assert.FileExists(t, result.RecoveredManifestPath)

	manifest, readErr := ReadManifest(ManifestPath(destDir))
	require.NoError(t, readErr)
	require.NotNil(t, manifest)
	assert.Len(t, manifest.Entries, 1)
}

func TestArchive_Integration_ContinuesAfterSourceFailure(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("permission-based unreadable file test is not reliable on Windows")
	}

	rc := testutil.TestRuntimeContext(t)

	srcDir := t.TempDir()
	destDir := filepath.Join(t.TempDir(), "archive")

	sessionsDir := filepath.Join(srcDir, "sessions")
	require.NoError(t, os.MkdirAll(sessionsDir, 0755))
	require.NoError(t, os.WriteFile(
		filepath.Join(sessionsDir, "good-chat.jsonl"),
		[]byte(`{"role":"user","content":"good"}`), 0644))
	badPath := filepath.Join(sessionsDir, "bad-chat.jsonl")
	require.NoError(t, os.WriteFile(
		badPath,
		[]byte(`{"role":"user","content":"bad"}`), 0644))
	require.NoError(t, os.Chmod(badPath, 0000))
	defer func() { _ = os.Chmod(badPath, 0644) }()

	result, err := Archive(rc, Options{
		Sources: []string{srcDir},
		Dest:    destDir,
	})
	require.NoError(t, err)
	assert.Equal(t, 1, result.UniqueFiles)
	assert.Equal(t, 1, result.FailureCount)
	assert.Len(t, result.Failures, 1)
	assert.Equal(t, "hash", result.Failures[0].Stage)
}
