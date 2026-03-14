package chats

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testRC() *eos_io.RuntimeContext {
	return eos_io.NewContext(context.Background(), "chats-test")
}

func TestEncodeProjectPath(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"standard path", "/opt/eos", "opt-eos"},
		{"home path", "/home/henry/projects/myapp", "home-henry-projects-myapp"},
		{"root path", "/", ""},
		{"already clean", "myproject", "myproject"},
		{"dots and spaces", "/opt/my.project/v2", "opt-my-project-v2"},
		{"windows-like", "C:\\Users\\henry", "C--Users-henry"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := EncodeProjectPath(tt.input)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestDefaultSources_ReturnsExpectedCount(t *testing.T) {
	sources := DefaultSources("/home/test", "/home/test/.config", "/opt/eos")
	// 13 sources defined in DefaultSources
	assert.Len(t, sources, 13)
}

func TestDefaultSources_ContainsExpectedTools(t *testing.T) {
	sources := DefaultSources("/home/test", "/home/test/.config", "/opt/eos")

	names := make(map[string]bool)
	for _, s := range sources {
		names[s.Name] = true
	}

	expectedTools := []string{
		"claude-code", "claude-code-all", "claude-code-index", "claude-code-history",
		"windsurf", "cursor", "codex", "cline", "roo-code", "copilot",
		"aider", "amazon-q", "continue",
	}

	for _, tool := range expectedTools {
		assert.True(t, names[tool], "missing tool: %s", tool)
	}
}

func TestDefaultSources_UsesEncodedProjectPath(t *testing.T) {
	sources := DefaultSources("/home/test", "/home/test/.config", "/opt/eos")
	// claude-code source should contain the encoded path
	assert.Contains(t, sources[0].Path, "opt-eos")
}

func TestDiscover_FindsExistingSources(t *testing.T) {
	rc := testRC()
	tmpDir := t.TempDir()

	// Create a mock claude-code sessions directory with a .jsonl file
	sessionsDir := filepath.Join(tmpDir, "sessions")
	require.NoError(t, os.MkdirAll(sessionsDir, 0755))
	require.NoError(t, os.WriteFile(
		filepath.Join(sessionsDir, "test.jsonl"),
		[]byte(`{"role":"user","content":"hello"}`),
		0644,
	))

	// Create a mock aider history file
	aiderFile := filepath.Join(tmpDir, ".aider.chat.history.md")
	require.NoError(t, os.WriteFile(aiderFile, []byte("# Chat\nHello"), 0644))

	sources := []ChatSource{
		{Name: "claude-code", Path: sessionsDir, Pattern: "*.jsonl"},
		{Name: "aider", Path: aiderFile, Pattern: "*"},
		{Name: "missing-tool", Path: filepath.Join(tmpDir, "nonexistent"), Pattern: "*"},
	}

	discovered := Discover(rc, sources)

	assert.Len(t, discovered, 2)
	assert.Equal(t, "claude-code", discovered[0].Name)
	assert.Equal(t, 1, discovered[0].FileCount)
	assert.Greater(t, discovered[0].TotalSize, int64(0))
	assert.Equal(t, "aider", discovered[1].Name)
	assert.Equal(t, 1, discovered[1].FileCount)
}

func TestDiscover_SkipsEmptyFiles(t *testing.T) {
	rc := testRC()
	tmpDir := t.TempDir()

	// Create an empty file
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "empty.jsonl"), nil, 0644))

	sources := []ChatSource{
		{Name: "empty-source", Path: tmpDir, Pattern: "*.jsonl"},
	}

	discovered := Discover(rc, sources)
	assert.Empty(t, discovered)
}

func TestDiscover_SkipsNonexistentPaths(t *testing.T) {
	rc := testRC()
	sources := []ChatSource{
		{Name: "ghost", Path: "/nonexistent/path/that/does/not/exist", Pattern: "*"},
	}

	discovered := Discover(rc, sources)
	assert.Empty(t, discovered)
}

func TestDiscover_PatternFiltering(t *testing.T) {
	rc := testRC()
	tmpDir := t.TempDir()

	// Create files with different extensions
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "chat.json"), []byte("{}"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "data.txt"), []byte("text"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "other.json"), []byte("[]"), 0644))

	sources := []ChatSource{
		{Name: "json-only", Path: tmpDir, Pattern: "*.json"},
	}

	discovered := Discover(rc, sources)
	require.Len(t, discovered, 1)
	assert.Equal(t, 2, discovered[0].FileCount) // Only .json files
}

func TestCountMatchingFiles_Wildcard(t *testing.T) {
	tmpDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "a.txt"), []byte("a"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "b.json"), []byte("b"), 0644))

	count, size := countMatchingFiles(tmpDir, "*")
	assert.Equal(t, 2, count)
	assert.Equal(t, int64(2), size)
}

func TestCountMatchingFiles_SpecificPattern(t *testing.T) {
	tmpDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "a.jsonl"), []byte("data"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "b.txt"), []byte("text"), 0644))

	count, size := countMatchingFiles(tmpDir, "*.jsonl")
	assert.Equal(t, 1, count)
	assert.Equal(t, int64(4), size)
}

func TestCountMatchingFiles_EmptyDir(t *testing.T) {
	tmpDir := t.TempDir()

	count, size := countMatchingFiles(tmpDir, "*")
	assert.Equal(t, 0, count)
	assert.Equal(t, int64(0), size)
}

func TestCountMatchingFiles_NestedFiles(t *testing.T) {
	tmpDir := t.TempDir()
	subdir := filepath.Join(tmpDir, "sub")
	require.NoError(t, os.MkdirAll(subdir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(subdir, "nested.json"), []byte("{}"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "root.json"), []byte("{}"), 0644))

	count, _ := countMatchingFiles(tmpDir, "*.json")
	assert.Equal(t, 2, count)
}
