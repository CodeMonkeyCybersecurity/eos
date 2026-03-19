package chatarchive

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsCandidate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		normPath string
		osPath   string
		expected bool
	}{
		// JSONL files
		{name: "jsonl under dev", normPath: "/home/user/dev/project/chat.jsonl", osPath: "/home/user/dev/project/chat.jsonl", expected: true},
		{name: "jsonl in sessions dir", normPath: "/home/user/.codex/sessions/log.jsonl", osPath: "/home/user/.codex/sessions/log.jsonl", expected: true},
		{name: "jsonl with chat in name", normPath: "/tmp/my-chat-log.jsonl", osPath: "/tmp/my-chat-log.jsonl", expected: true},
		{name: "jsonl with session in name", normPath: "/tmp/session-2024.jsonl", osPath: "/tmp/session-2024.jsonl", expected: true},
		{name: "jsonl with no clues outside dev", normPath: "/tmp/random.jsonl", osPath: "/tmp/random.jsonl", expected: false},

		// Chat files
		{name: "chat extension always included", normPath: "/some/path/file.chat", osPath: "/some/path/file.chat", expected: true},

		// HTML files
		{name: "html with chat in name", normPath: "/tmp/chat-export.html", osPath: "/tmp/chat-export.html", expected: true},
		{name: "html with conversation in name", normPath: "/tmp/conversation-2024.html", osPath: "/tmp/conversation-2024.html", expected: true},
		{name: "html with transcript in name", normPath: "/tmp/transcript.html", osPath: "/tmp/transcript.html", expected: true},
		{name: "html without clues", normPath: "/tmp/index.html", osPath: "/tmp/index.html", expected: false},

		// Memory files
		{name: "memory.md always included", normPath: "/some/deep/path/memory.md", osPath: "/some/deep/path/memory.md", expected: true},

		// Path clue directories
		{name: "file in .claude dir", normPath: "/home/user/.claude/projects/data.jsonl", osPath: "/home/user/.claude/projects/data.jsonl", expected: true},
		{name: "file in .openclaw dir", normPath: "/home/user/.openclaw/agents/log.jsonl", osPath: "/home/user/.openclaw/agents/log.jsonl", expected: true},
		{name: "file in .windsurf dir", normPath: "/home/user/.windsurf/sessions/s1.jsonl", osPath: "/home/user/.windsurf/sessions/s1.jsonl", expected: true},
		{name: "file in .cursor dir", normPath: "/home/user/.cursor/data.jsonl", osPath: "/home/user/.cursor/data.jsonl", expected: true},
		{name: "file in transcripts dir", normPath: "/data/transcripts/file.jsonl", osPath: "/data/transcripts/file.jsonl", expected: true},
		{name: "file in chats dir", normPath: "/data/chats/file.jsonl", osPath: "/data/chats/file.jsonl", expected: true},

		// Windows-style paths normalised to forward slashes
		{name: "windows path normalised", normPath: "c:/users/henry/.claude/sessions/log.jsonl", osPath: "C:\\Users\\henry\\.claude\\sessions\\log.jsonl", expected: true},
		{name: "windows dev path", normPath: "c:/users/henry/dev/project/file.jsonl", osPath: "C:\\Users\\henry\\Dev\\project\\file.jsonl", expected: true},

		// Non-matching files
		{name: "go source file", normPath: "/home/user/dev/main.go", osPath: "/home/user/dev/main.go", expected: false},
		{name: "random json without clues", normPath: "/tmp/config.json", osPath: "/tmp/config.json", expected: false},
		{name: "random text file", normPath: "/tmp/notes.txt", osPath: "/tmp/notes.txt", expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := isCandidate(tt.normPath, tt.osPath)
			assert.Equal(t, tt.expected, got, "isCandidate(%q)", tt.normPath)
		})
	}
}

func TestIsExcludedArchiveDir(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		normPath string
		expected bool
	}{
		{name: "chat-archive output dir", normPath: "/home/user/dev/eos/outputs/chat-archive", expected: true},
		{name: "desktop conversation archive", normPath: "/home/user/desktop/conversationarchive", expected: true},
		{name: "normal directory", normPath: "/home/user/dev/project", expected: false},
		{name: "windows chat-archive path", normPath: "c:/users/henry/dev/eos/outputs/chat-archive", expected: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := isExcludedArchiveDir(tt.normPath)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestNormalise(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{name: "unix path unchanged", input: "/home/user/Dev", expected: "/home/user/dev"},
		{name: "mixed case lowered", input: "/Home/USER/Dev", expected: "/home/user/dev"},
		{name: "already normalised", input: "/tmp/test", expected: "/tmp/test"},
	}
	// filepath.ToSlash only converts OS-native separators.
	// On Windows \ is the separator; on Unix it's a valid filename char.
	if runtime.GOOS == "windows" {
		tests = append(tests, struct {
			name     string
			input    string
			expected string
		}{name: "backslashes to forward on windows", input: "C:\\Users\\Henry\\Dev", expected: "c:/users/henry/dev"})
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := normalise(tt.input)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestDiscoverTranscriptFiles(t *testing.T) {
	t.Parallel()
	rc := testutil.TestRuntimeContext(t)

	// Create a temp directory structure
	dir := t.TempDir()
	sessionsDir := filepath.Join(dir, "sessions")
	require.NoError(t, os.MkdirAll(sessionsDir, 0755))

	// Create test files
	require.NoError(t, os.WriteFile(filepath.Join(sessionsDir, "chat.jsonl"), []byte(`{"role":"user"}`), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(sessionsDir, "notes.txt"), []byte("not a chat"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "memory.md"), []byte("# Memory"), 0644))

	// Create a .git dir that should be skipped
	gitDir := filepath.Join(dir, ".git")
	require.NoError(t, os.MkdirAll(gitDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(gitDir, "chat.jsonl"), []byte("should be skipped"), 0644))

	dest := filepath.Join(dir, "archive-output")
	files, err := DiscoverTranscriptFiles(rc, []string{dir}, dest)
	require.NoError(t, err)

	// Should find chat.jsonl in sessions dir and memory.md but not notes.txt or .git/chat.jsonl
	assert.GreaterOrEqual(t, len(files), 2, "should find at least chat.jsonl and memory.md")

	// Verify .git contents are excluded
	for _, f := range files {
		assert.NotContains(t, filepath.ToSlash(f), "/.git/", "should not include .git files")
	}

	// Verify memory.md is included
	hasMemory := false
	for _, f := range files {
		if filepath.Base(f) == "memory.md" {
			hasMemory = true
			break
		}
	}
	assert.True(t, hasMemory, "should discover memory.md")
}

func TestDiscoverTranscriptFiles_SkipsDestDir(t *testing.T) {
	t.Parallel()
	rc := testutil.TestRuntimeContext(t)

	dir := t.TempDir()
	destDir := filepath.Join(dir, "archive")
	require.NoError(t, os.MkdirAll(destDir, 0755))

	// Put a file in the dest dir — it should be excluded
	require.NoError(t, os.WriteFile(filepath.Join(destDir, "existing-chat.jsonl"), []byte(`{"role":"user"}`), 0644))

	// Put a file outside dest dir
	sessionsDir := filepath.Join(dir, "sessions")
	require.NoError(t, os.MkdirAll(sessionsDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(sessionsDir, "new-chat.jsonl"), []byte(`{"role":"user"}`), 0644))

	files, err := DiscoverTranscriptFiles(rc, []string{dir}, destDir)
	require.NoError(t, err)

	for _, f := range files {
		assert.False(t, isSubpath(f, destDir), "should not include files from dest dir: %s", f)
	}
}

func TestDiscoverTranscriptFiles_NonexistentRoot(t *testing.T) {
	t.Parallel()
	rc := testutil.TestRuntimeContext(t)

	files, err := DiscoverTranscriptFiles(rc, []string{"/nonexistent/path"}, "/tmp/dest")
	require.NoError(t, err, "nonexistent root should be skipped, not error")
	assert.Empty(t, files)
}

func TestDiscoverTranscriptFiles_EmptyRoots(t *testing.T) {
	t.Parallel()
	rc := testutil.TestRuntimeContext(t)

	files, err := DiscoverTranscriptFiles(rc, []string{}, "/tmp/dest")
	require.NoError(t, err)
	assert.Empty(t, files)
}

func TestIsJSONTranscript(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		content  string
		expected bool
	}{
		{
			name:     "messages with role and content",
			content:  `{"messages": [{"role": "user", "content": "hello"}]}`,
			expected: true,
		},
		{
			name:     "conversation with content",
			content:  `{"conversation": "test", "content": "data"}`,
			expected: true,
		},
		{
			name:     "config file no chat markers",
			content:  `{"database": "postgres", "host": "localhost"}`,
			expected: false,
		},
		{
			name:     "empty json",
			content:  `{}`,
			expected: false,
		},
		{
			name:     "messages without role or content",
			content:  `{"messages": [{"text": "hello"}]}`,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			path := filepath.Join(dir, "test.json")
			require.NoError(t, os.WriteFile(path, []byte(tt.content), 0644))

			got := isJSONTranscript(path)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestIsJSONTranscript_LargeFile(t *testing.T) {
	t.Parallel()
	// Verify bounded read: create a file larger than jsonValidationBufSize
	// with chat markers only after the buffer boundary.
	dir := t.TempDir()
	path := filepath.Join(dir, "large.json")

	// Write 8KB of padding followed by chat markers
	padding := make([]byte, jsonValidationBufSize+100)
	for i := range padding {
		padding[i] = ' '
	}
	content := append(padding, []byte(`{"messages": [{"role": "user"}]}`)...)
	require.NoError(t, os.WriteFile(path, content, 0644))

	// Should return false because markers are past the read buffer
	assert.False(t, isJSONTranscript(path), "should not detect markers past buffer boundary")
}

func TestIsCandidate_JSONWithPathClue(t *testing.T) {
	t.Parallel()

	// JSON file in a sessions directory with valid chat content
	dir := t.TempDir()
	sessionsDir := filepath.Join(dir, "sessions")
	require.NoError(t, os.MkdirAll(sessionsDir, 0755))
	path := filepath.Join(sessionsDir, "data.json")
	require.NoError(t, os.WriteFile(path, []byte(`{"messages":[{"role":"user","content":"hi"}]}`), 0644))

	normPath := normalise(path)
	assert.True(t, isCandidate(normPath, path), "json file in sessions dir with chat content should match")
}

func TestIsJSONTranscript_NonexistentFile(t *testing.T) {
	t.Parallel()
	assert.False(t, isJSONTranscript("/nonexistent/file.json"))
}

// isSubpath checks if child is under parent directory.
func isSubpath(child, parent string) bool {
	rel, err := filepath.Rel(parent, child)
	if err != nil {
		return false
	}
	return len(rel) > 0 && rel[0] != '.'
}
