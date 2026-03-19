package chatarchive

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultSources(t *testing.T) {
	t.Parallel()

	sources := DefaultSources()
	assert.NotEmpty(t, sources, "should return at least one default source")

	// All sources should start with ~
	for _, s := range sources {
		assert.True(t, len(s) > 0, "source path should not be empty")
		assert.Equal(t, "~", string(s[0]), "source paths should start with ~")
	}

	// Should include common AI coding tool directories
	found := map[string]bool{}
	for _, s := range sources {
		switch s {
		case "~/.claude":
			found["claude"] = true
		case "~/.codex":
			found["codex"] = true
		case "~/.openclaw/agents/main/sessions":
			found["openclaw"] = true
		}
	}
	assert.True(t, found["claude"], "should include Claude Code directory")
	assert.True(t, found["codex"], "should include Codex directory")
	assert.True(t, found["openclaw"], "should include OpenClaw directory")
}

func TestDefaultDest(t *testing.T) {
	t.Parallel()

	dest := DefaultDest()
	assert.NotEmpty(t, dest)
	assert.Contains(t, dest, "chat-archive")
}

func TestExpandSources(t *testing.T) {
	t.Parallel()

	sources := []string{"~/Dev", "~/test"}
	expanded := ExpandSources(sources)

	assert.Len(t, expanded, 2)
	for _, s := range expanded {
		assert.NotContains(t, s, "~", "~ should be expanded")
	}
}

func TestExpandSources_EmptyList(t *testing.T) {
	t.Parallel()

	expanded := ExpandSources([]string{})
	assert.Empty(t, expanded)
}

func TestDefaultSources_PlatformSpecific(t *testing.T) {
	t.Parallel()

	sources := DefaultSources()
	// On all platforms, should include Claude Code and common dev dirs
	switch runtime.GOOS {
	case "darwin", "linux", "windows":
		assert.GreaterOrEqual(t, len(sources), 5,
			"should have at least 5 default sources on %s", runtime.GOOS)
	}
}

func TestResolveOptions(t *testing.T) {
	t.Parallel()

	destDir := t.TempDir()
	sourceDir := t.TempDir()

	opts, err := ResolveOptions(Options{
		Sources: []string{sourceDir, sourceDir, filepath.Join(sourceDir, "..", filepath.Base(sourceDir))},
		Dest:    destDir,
	})
	require.NoError(t, err)

	assert.NotEmpty(t, opts.Sources)
	assert.Len(t, opts.Sources, 1, "duplicate sources should be removed after absolute path resolution")
	assert.Equal(t, filepath.Clean(destDir), opts.Dest)
}

func TestResolveOptions_UsesDefaults(t *testing.T) {
	t.Parallel()

	opts, err := ResolveOptions(Options{})
	require.NoError(t, err)

	assert.NotEmpty(t, opts.Sources)
	assert.NotEmpty(t, opts.Dest)
	assert.True(t, filepath.IsAbs(opts.Dest), "destination should be absolute")
}

func TestDefaultDest_PlatformAware(t *testing.T) {
	t.Parallel()

	dest := DefaultDest()
	assert.NotEmpty(t, dest)

	home, err := os.UserHomeDir()
	require.NoError(t, err)

	switch runtime.GOOS {
	case "windows", "darwin":
		assert.Contains(t, dest, home)
	default:
		assert.True(t, filepath.IsAbs(dest))
	}
}

func TestDefaultDestForPlatform(t *testing.T) {
	t.Parallel()

	home := filepath.Join(string(filepath.Separator), "home", "henry")
	assert.Equal(t,
		filepath.Join(home, "AppData", "Local", "eos", "chat-archive"),
		defaultDestForPlatform("windows", home, "", ""),
	)
	assert.Equal(t,
		filepath.Join("C:\\Users\\Henry\\AppData\\Local", "eos", "chat-archive"),
		defaultDestForPlatform("windows", home, "C:\\Users\\Henry\\AppData\\Local", ""),
	)
	assert.Equal(t,
		filepath.Join(home, "Library", "Application Support", "eos", "chat-archive"),
		defaultDestForPlatform("darwin", home, "", ""),
	)
	assert.Equal(t,
		filepath.Join(home, ".local", "share", "eos", "chat-archive"),
		defaultDestForPlatform("linux", home, "", ""),
	)
	assert.Equal(t,
		filepath.Join("/xdg/data", "eos", "chat-archive"),
		defaultDestForPlatform("linux", home, "", "/xdg/data"),
	)
}

func TestDefaultDest_HomeFallback(t *testing.T) {
	t.Parallel()

	original := userHomeDir
	userHomeDir = func() (string, error) {
		return "", errors.New("boom")
	}
	t.Cleanup(func() {
		userHomeDir = original
	})

	assert.Equal(t, filepath.Join(".", "chat-archive"), DefaultDest())
}
