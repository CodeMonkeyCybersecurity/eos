package chats

import (
	"archive/tar"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
)

// setupTestSource creates a temporary directory with mock chat files.
// Returns (repoRoot, homeDir, configDir).
func setupTestSource(t *testing.T) (string, string, string) {
	t.Helper()

	repoRoot := t.TempDir()
	homeDir := t.TempDir()
	configDir := t.TempDir()

	// Create mock claude-code sessions matching EncodeProjectPath(repoRoot)
	encoded := EncodeProjectPath(repoRoot)
	sessionsDir := filepath.Join(homeDir, ".claude", "projects", encoded, "sessions")
	require.NoError(t, os.MkdirAll(sessionsDir, 0755))
	require.NoError(t, os.WriteFile(
		filepath.Join(sessionsDir, "session1.jsonl"),
		[]byte(`{"role":"user","content":"hello"}`+"\n"),
		0644,
	))
	require.NoError(t, os.WriteFile(
		filepath.Join(sessionsDir, "session2.jsonl"),
		[]byte(`{"role":"assistant","content":"hi"}`+"\n"),
		0644,
	))

	// Create mock aider history
	require.NoError(t, os.WriteFile(
		filepath.Join(repoRoot, ".aider.chat.history.md"),
		[]byte("# Aider Chat History\n\nSome content here.\n"),
		0644,
	))

	return repoRoot, homeDir, configDir
}

func TestRunBackup_EndToEnd(t *testing.T) {
	rc := testRC()
	repoRoot, homeDir, configDir := setupTestSource(t)

	result, err := RunBackup(rc, BackupConfig{
		RepoRoot:  repoRoot,
		HomeDir:   homeDir,
		ConfigDir: configDir,
	})
	require.NoError(t, err)
	require.NotNil(t, result)

	// Should find claude-code and aider sources
	assert.GreaterOrEqual(t, result.SourcesFound, 2)
	assert.Greater(t, result.TotalFiles, 0)
	assert.Greater(t, result.NewFiles, 0)
	assert.Equal(t, 0, result.ChangedFiles)
	assert.Equal(t, 0, result.UnchangedFiles)
	assert.NotEmpty(t, result.ArchivePath)

	// Verify archive exists and is valid tar.gz
	assertValidTarGz(t, result.ArchivePath)

	// Verify manifest was created
	manifestPath := filepath.Join(repoRoot, BackupSubdir, ManifestFile)
	assert.FileExists(t, manifestPath)

	// Verify log was created
	logPath := filepath.Join(repoRoot, BackupSubdir, LogFile)
	assert.FileExists(t, logPath)

	// Verify .gitignore was created
	gitignorePath := filepath.Join(repoRoot, GitignoreRelPath)
	assert.FileExists(t, gitignorePath)
}

func TestRunBackup_Deduplication(t *testing.T) {
	rc := testRC()
	repoRoot, homeDir, configDir := setupTestSource(t)

	config := BackupConfig{
		RepoRoot:  repoRoot,
		HomeDir:   homeDir,
		ConfigDir: configDir,
	}

	// First backup: everything is new
	result1, err := RunBackup(rc, config)
	require.NoError(t, err)
	assert.Greater(t, result1.NewFiles, 0)
	assert.Equal(t, 0, result1.UnchangedFiles)

	// Second backup: everything should be unchanged
	result2, err := RunBackup(rc, config)
	require.NoError(t, err)
	assert.Equal(t, 0, result2.NewFiles)
	assert.Equal(t, 0, result2.ChangedFiles)
	assert.Greater(t, result2.UnchangedFiles, 0)
	assert.Empty(t, result2.ArchivePath) // No archive created
}

func TestRunBackup_DetectsChangedFiles(t *testing.T) {
	rc := testRC()
	repoRoot, homeDir, configDir := setupTestSource(t)

	config := BackupConfig{
		RepoRoot:  repoRoot,
		HomeDir:   homeDir,
		ConfigDir: configDir,
	}

	// First backup
	_, err := RunBackup(rc, config)
	require.NoError(t, err)

	// Modify a file
	encoded := EncodeProjectPath(repoRoot)
	sessionsDir := filepath.Join(homeDir, ".claude", "projects", encoded, "sessions")
	require.NoError(t, os.WriteFile(
		filepath.Join(sessionsDir, "session1.jsonl"),
		[]byte(`{"role":"user","content":"modified content"}`+"\n"),
		0644,
	))

	// Second backup: should detect changed file
	result2, err := RunBackup(rc, config)
	require.NoError(t, err)
	assert.Greater(t, result2.ChangedFiles, 0)
	assert.NotEmpty(t, result2.ArchivePath)
}

func TestRunBackup_DryRun(t *testing.T) {
	rc := testRC()
	repoRoot, homeDir, configDir := setupTestSource(t)

	result, err := RunBackup(rc, BackupConfig{
		RepoRoot:  repoRoot,
		HomeDir:   homeDir,
		ConfigDir: configDir,
		DryRun:    true,
	})
	require.NoError(t, err)
	assert.Greater(t, result.NewFiles, 0)
	assert.Empty(t, result.ArchivePath) // No archive in dry-run

	// Verify no backup directory was created
	backupDir := filepath.Join(repoRoot, BackupSubdir)
	_, statErr := os.Stat(backupDir)
	assert.True(t, os.IsNotExist(statErr), "backup dir should not exist in dry-run")
}

func TestRunBackup_NoSources(t *testing.T) {
	rc := testRC()
	emptyHome := t.TempDir()
	emptyConfig := t.TempDir()
	emptyRepo := t.TempDir()

	result, err := RunBackup(rc, BackupConfig{
		RepoRoot:  emptyRepo,
		HomeDir:   emptyHome,
		ConfigDir: emptyConfig,
	})
	require.NoError(t, err)
	assert.Equal(t, 0, result.SourcesFound)
	assert.Equal(t, 0, result.TotalFiles)
	assert.Empty(t, result.ArchivePath)
}

func TestGenerateManifest(t *testing.T) {
	tmpDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "a.txt"), []byte("hello"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "b.txt"), []byte("world"), 0644))

	entries, err := generateManifest(tmpDir)
	require.NoError(t, err)
	assert.Len(t, entries, 2)

	// Entries should be sorted by filename
	assert.Equal(t, "a.txt", entries[0].File)
	assert.Equal(t, "b.txt", entries[1].File)

	// Hashes should be valid hex SHA-256 (64 characters)
	assert.Len(t, entries[0].Hash, 64)
	assert.Len(t, entries[1].Hash, 64)

	// Different content should produce different hashes
	assert.NotEqual(t, entries[0].Hash, entries[1].Hash)
}

func TestGenerateManifest_SkipsEmptyFiles(t *testing.T) {
	tmpDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "empty.txt"), nil, 0644))
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "notempty.txt"), []byte("data"), 0644))

	entries, err := generateManifest(tmpDir)
	require.NoError(t, err)
	assert.Len(t, entries, 1)
	assert.Equal(t, "notempty.txt", entries[0].File)
}

func TestLoadManifest_ValidFile(t *testing.T) {
	tmpDir := t.TempDir()
	manifestPath := filepath.Join(tmpDir, ManifestFile)
	content := "abc123  file1.txt\ndef456  path/to/file2.json\n"
	require.NoError(t, os.WriteFile(manifestPath, []byte(content), 0644))

	m := loadManifest(manifestPath)
	assert.Len(t, m, 2)
	assert.Equal(t, "abc123", m["file1.txt"])
	assert.Equal(t, "def456", m["path/to/file2.json"])
}

func TestLoadManifest_MissingFile(t *testing.T) {
	m := loadManifest("/nonexistent/manifest.sha256")
	assert.Empty(t, m)
}

func TestLoadManifest_EmptyFile(t *testing.T) {
	tmpDir := t.TempDir()
	manifestPath := filepath.Join(tmpDir, ManifestFile)
	require.NoError(t, os.WriteFile(manifestPath, nil, 0644))

	m := loadManifest(manifestPath)
	assert.Empty(t, m)
}

func TestDiffManifests_AllNew(t *testing.T) {
	entries := []manifestEntry{
		{File: "a.txt", Hash: "hash1"},
		{File: "b.txt", Hash: "hash2"},
	}
	prev := map[string]string{}

	newFiles, changed, unchanged, toArchive := diffManifests(entries, prev)
	assert.Equal(t, 2, newFiles)
	assert.Equal(t, 0, changed)
	assert.Equal(t, 0, unchanged)
	assert.Len(t, toArchive, 2)
}

func TestDiffManifests_AllUnchanged(t *testing.T) {
	entries := []manifestEntry{
		{File: "a.txt", Hash: "hash1"},
		{File: "b.txt", Hash: "hash2"},
	}
	prev := map[string]string{
		"a.txt": "hash1",
		"b.txt": "hash2",
	}

	newFiles, changed, unchanged, toArchive := diffManifests(entries, prev)
	assert.Equal(t, 0, newFiles)
	assert.Equal(t, 0, changed)
	assert.Equal(t, 2, unchanged)
	assert.Empty(t, toArchive)
}

func TestDiffManifests_Mixed(t *testing.T) {
	entries := []manifestEntry{
		{File: "existing.txt", Hash: "newhash"},    // changed
		{File: "same.txt", Hash: "samehash"},       // unchanged
		{File: "brandnew.txt", Hash: "freshhhash"}, // new
	}
	prev := map[string]string{
		"existing.txt": "oldhash",
		"same.txt":     "samehash",
	}

	newFiles, changed, unchanged, toArchive := diffManifests(entries, prev)
	assert.Equal(t, 1, newFiles)
	assert.Equal(t, 1, changed)
	assert.Equal(t, 1, unchanged)
	assert.Len(t, toArchive, 2)
	assert.Contains(t, toArchive, "existing.txt")
	assert.Contains(t, toArchive, "brandnew.txt")
}

func TestWriteManifest_RoundTrip(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, ManifestFile)

	entries := []manifestEntry{
		{File: "dir/file.txt", Hash: "abc123"},
		{File: "root.json", Hash: "def456"},
	}

	require.NoError(t, writeManifest(path, entries))

	// Read back
	m := loadManifest(path)
	assert.Len(t, m, 2)
	assert.Equal(t, "abc123", m["dir/file.txt"])
	assert.Equal(t, "def456", m["root.json"])
}

func TestCreateArchive(t *testing.T) {
	tmpDir := t.TempDir()

	// Create source files
	require.NoError(t, os.MkdirAll(filepath.Join(tmpDir, "src", "tool"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "src", "tool", "chat.jsonl"), []byte("data"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "src", "top.txt"), []byte("top"), 0644))

	archivePath := filepath.Join(tmpDir, "test.tar.gz")
	files := []string{"tool/chat.jsonl", "top.txt"}
	require.NoError(t, createArchive(archivePath, filepath.Join(tmpDir, "src"), files))

	// Verify archive contents
	names := extractTarGzFileNames(t, archivePath)
	assert.Contains(t, names, "tool/chat.jsonl")
	assert.Contains(t, names, "top.txt")
}

func TestEnsureGitignore_CreatesNew(t *testing.T) {
	tmpDir := t.TempDir()
	require.NoError(t, ensureGitignore(tmpDir))

	path := filepath.Join(tmpDir, GitignoreRelPath)
	assert.FileExists(t, path)

	content, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Contains(t, string(content), "Chat backups are local data")
	assert.Contains(t, string(content), "!.gitignore")
}

func TestEnsureGitignore_Idempotent(t *testing.T) {
	tmpDir := t.TempDir()
	require.NoError(t, ensureGitignore(tmpDir))

	// Write custom content to verify it's not overwritten
	path := filepath.Join(tmpDir, GitignoreRelPath)
	require.NoError(t, os.WriteFile(path, []byte("custom"), 0644))

	require.NoError(t, ensureGitignore(tmpDir))

	content, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "custom", string(content))
}

func TestCopyFile(t *testing.T) {
	tmpDir := t.TempDir()
	src := filepath.Join(tmpDir, "src.txt")
	dst := filepath.Join(tmpDir, "dst.txt")

	require.NoError(t, os.WriteFile(src, []byte("content"), 0644))
	require.NoError(t, copyFile(src, dst))

	content, err := os.ReadFile(dst)
	require.NoError(t, err)
	assert.Equal(t, "content", string(content))
}

func TestCopyFile_MissingSrc(t *testing.T) {
	tmpDir := t.TempDir()
	err := copyFile(filepath.Join(tmpDir, "nope"), filepath.Join(tmpDir, "dst"))
	assert.Error(t, err)
}

func TestAppendLog(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, LogFile)

	result := &BackupResult{
		NewFiles:       3,
		ChangedFiles:   1,
		UnchangedFiles: 5,
		ArchivePath:    "/tmp/test.tar.gz",
	}
	appendLog(logPath, result, "2026-03-14-1430")

	content, err := os.ReadFile(logPath)
	require.NoError(t, err)
	line := string(content)
	assert.Contains(t, line, "archived=4")
	assert.Contains(t, line, "new=3")
	assert.Contains(t, line, "changed=1")
	assert.Contains(t, line, "unchanged=5")
}

func TestCollectSource_SingleFile(t *testing.T) {
	tmpDir := t.TempDir()
	stagingDir := t.TempDir()

	srcFile := filepath.Join(tmpDir, "history.md")
	require.NoError(t, os.WriteFile(srcFile, []byte("chat"), 0644))

	logger := otelzap.Ctx(testRC().Ctx)
	count := collectSource(logger, ChatSource{Name: "aider", Path: srcFile, Pattern: "*"}, stagingDir)
	assert.Equal(t, 1, count)

	// Verify file was copied
	assert.FileExists(t, filepath.Join(stagingDir, "aider", "history.md"))
}

func TestCollectSource_DirectoryWithPattern(t *testing.T) {
	tmpDir := t.TempDir()
	stagingDir := t.TempDir()

	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "a.json"), []byte("{}"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "b.txt"), []byte("text"), 0644))

	logger := otelzap.Ctx(testRC().Ctx)
	count := collectSource(logger, ChatSource{Name: "test", Path: tmpDir, Pattern: "*.json"}, stagingDir)
	assert.Equal(t, 1, count) // Only .json file
}

func TestCollectSource_NonexistentPath(t *testing.T) {
	stagingDir := t.TempDir()
	logger := otelzap.Ctx(testRC().Ctx)
	count := collectSource(logger, ChatSource{Name: "ghost", Path: "/does/not/exist", Pattern: "*"}, stagingDir)
	assert.Equal(t, 0, count)
}

// --- test helpers ---

func assertValidTarGz(t *testing.T, path string) {
	t.Helper()
	names := extractTarGzFileNames(t, path)
	assert.NotEmpty(t, names, "archive should contain at least one file")
}

func extractTarGzFileNames(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(path)
	require.NoError(t, err)
	defer f.Close()

	gzr, err := gzip.NewReader(f)
	require.NoError(t, err)
	defer gzr.Close()

	tr := tar.NewReader(gzr)
	var names []string
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		if !strings.HasSuffix(header.Name, "/") {
			names = append(names, header.Name)
		}
	}
	return names
}
