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

func TestDefaultSourcesForPlatform(t *testing.T) {
	t.Parallel()

	home := filepath.Join(string(filepath.Separator), "home", "henry")

	windowsSources := defaultSourcesForPlatform("windows", home, `C:\Users\Henry\AppData\Roaming`, `C:\Users\Henry\AppData\Local`)
	assert.Contains(t, windowsSources, "~/.claude")
	assert.Contains(t, windowsSources, filepath.Join(`C:\Users\Henry\AppData\Roaming`, "Cursor"))
	assert.Contains(t, windowsSources, filepath.Join(`C:\Users\Henry\AppData\Local`, "Windsurf"))

	darwinSources := defaultSourcesForPlatform("darwin", home, "", "")
	assert.Contains(t, darwinSources, filepath.Join(home, "Library", "Application Support", "Cursor"))
	assert.Contains(t, darwinSources, filepath.Join(home, "Library", "Application Support", "Windsurf"))

	linuxSources := defaultSourcesForPlatform("linux", home, "", "")
	assert.Contains(t, linuxSources, "~/.config/Cursor")
	assert.Contains(t, linuxSources, "~/.config/Windsurf")
}

func TestDefaultSourcesWithProvider_HomeError(t *testing.T) {
	t.Parallel()

	sources := defaultSourcesWithProvider("windows", func() (string, error) {
		return "", errors.New("boom")
	}, `C:\Users\Henry\AppData\Roaming`, "")

	assert.Contains(t, sources, "~/.claude")
	assert.Contains(t, sources, filepath.Join(`C:\Users\Henry\AppData\Roaming`, "Cursor"))
	assert.NotContains(t, sources, "")
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

	dest := defaultDestWithProvider(runtime.GOOS, func() (string, error) {
		return "", errors.New("boom")
	}, "", "")

	assert.Equal(t, filepath.Join(".", "chat-archive"), dest)
}

func TestExpandUserPath(t *testing.T) {
	t.Parallel()

	home := filepath.Join(string(filepath.Separator), "home", "henry")
	assert.Equal(t, home, expandUserPathWithHome("~", home))
	assert.Equal(t, filepath.Join(home, "Dev"), expandUserPathWithHome("~/Dev", home))
	assert.Equal(t, filepath.Join(home, "projects"), expandUserPathWithHome(`~\projects`, home))
	assert.Equal(t, "/tmp/plain", expandUserPathWithHome("/tmp/plain", home))
}

func TestExpandUserPathWithEmptyHome(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "~", expandUserPathWithHome("~", ""))
	assert.Equal(t, "~/Dev", expandUserPathWithHome("~/Dev", ""))
}

func TestUserProfileJoinAndUniqueNonEmptyStrings(t *testing.T) {
	t.Parallel()

	assert.Empty(t, userProfileJoin("", "Cursor"))
	assert.Equal(t,
		[]string{"a", "b"},
		uniqueNonEmptyStrings([]string{"a", "", "b", "a"}),
	)
}
