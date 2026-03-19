package chatarchive

import (
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
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
		case "~/.codex/sessions":
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
