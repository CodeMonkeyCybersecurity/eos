package chatbackup

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ═══════════════════════════════════════════════════════════════════════════
// Registry Tests - Validate tool registry completeness and correctness
// ═══════════════════════════════════════════════════════════════════════════

func TestDefaultToolRegistry_NotEmpty(t *testing.T) {
	registry := DefaultToolRegistry()
	require.NotEmpty(t, registry, "registry must contain at least one tool")
}

func TestDefaultToolRegistry_AllToolsHaveNames(t *testing.T) {
	registry := DefaultToolRegistry()
	for i, tool := range registry {
		assert.NotEmpty(t, tool.Name,
			"tool at index %d must have a name", i)
		assert.NotEmpty(t, tool.Description,
			"tool %q must have a description", tool.Name)
	}
}

func TestDefaultToolRegistry_AllToolsHavePaths(t *testing.T) {
	registry := DefaultToolRegistry()
	for _, tool := range registry {
		assert.NotEmpty(t, tool.Paths,
			"tool %q must have at least one path", tool.Name)
		for j, sp := range tool.Paths {
			assert.NotEmpty(t, sp.Path,
				"tool %q path at index %d must have a path", tool.Name, j)
			assert.NotEmpty(t, sp.Description,
				"tool %q path %q must have a description", tool.Name, sp.Path)
		}
	}
}

func TestDefaultToolRegistry_UniqueNames(t *testing.T) {
	registry := DefaultToolRegistry()
	seen := make(map[string]bool)
	for _, tool := range registry {
		assert.False(t, seen[tool.Name],
			"duplicate tool name %q in registry", tool.Name)
		seen[tool.Name] = true
	}
}

func TestDefaultToolRegistry_ClaudeCodePresent(t *testing.T) {
	// RATIONALE: Claude Code is the primary tool. If it's missing, something broke.
	registry := DefaultToolRegistry()
	found := false
	for _, tool := range registry {
		if tool.Name == "claude-code" {
			found = true

			// Verify critical paths
			hasProjects := false
			hasSettings := false
			for _, sp := range tool.Paths {
				if sp.Path == "~/.claude/projects" {
					hasProjects = true
				}
				if sp.Path == "~/.claude/settings.json" {
					hasSettings = true
				}
			}
			assert.True(t, hasProjects, "claude-code must back up ~/.claude/projects")
			assert.True(t, hasSettings, "claude-code must back up ~/.claude/settings.json")
			break
		}
	}
	assert.True(t, found, "claude-code must be in the registry")
}

func TestDefaultToolRegistry_CodexPresent(t *testing.T) {
	registry := DefaultToolRegistry()
	found := false
	for _, tool := range registry {
		if tool.Name == "codex" {
			found = true
			hasSessionsPath := false
			for _, sp := range tool.Paths {
				if sp.Path == "~/.codex/sessions" {
					hasSessionsPath = true
				}
			}
			assert.True(t, hasSessionsPath, "codex must back up ~/.codex/sessions")
			break
		}
	}
	assert.True(t, found, "codex must be in the registry")
}

func TestDefaultToolRegistry_MinimumToolCount(t *testing.T) {
	// RATIONALE: We support at least 8 tools (per adversarial review finding #6)
	registry := DefaultToolRegistry()
	assert.GreaterOrEqual(t, len(registry), 8,
		"registry should contain at least 8 AI tools (currently: %d)", len(registry))
}

func TestDefaultToolRegistry_AllPathsUseHomeExpansion(t *testing.T) {
	registry := DefaultToolRegistry()
	for _, tool := range registry {
		for _, sp := range tool.Paths {
			// All paths should start with ~ or be absolute
			if sp.Path[0] != '~' && sp.Path[0] != '/' {
				t.Errorf("tool %q path %q should start with ~ or /",
					tool.Name, sp.Path)
			}
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// Project Context Tests
// ═══════════════════════════════════════════════════════════════════════════

func TestProjectContextPatterns_NotEmpty(t *testing.T) {
	patterns := ProjectContextPatterns()
	require.NotEmpty(t, patterns)
}

func TestProjectContextPatterns_IncludesCriticalFiles(t *testing.T) {
	patterns := ProjectContextPatterns()
	patternSet := make(map[string]bool)
	for _, p := range patterns {
		patternSet[p] = true
	}

	assert.True(t, patternSet["CLAUDE.md"],
		"must include CLAUDE.md")
	assert.True(t, patternSet["AGENTS.md"],
		"must include AGENTS.md")
}

// ═══════════════════════════════════════════════════════════════════════════
// Default Excludes Tests
// ═══════════════════════════════════════════════════════════════════════════

func TestDefaultExcludes_NotEmpty(t *testing.T) {
	excludes := DefaultExcludes()
	require.NotEmpty(t, excludes)
}

func TestDefaultExcludes_ExcludesTelemetry(t *testing.T) {
	excludes := DefaultExcludes()
	found := false
	for _, e := range excludes {
		if e == ".claude/telemetry" {
			found = true
			break
		}
	}
	assert.True(t, found, "must exclude .claude/telemetry (privacy)")
}

func TestDefaultExcludes_ExcludesCache(t *testing.T) {
	excludes := DefaultExcludes()
	found := false
	for _, e := range excludes {
		if e == ".claude/cache" {
			found = true
			break
		}
	}
	assert.True(t, found, "must exclude .claude/cache (transient data)")
}

func TestDefaultExcludes_ExcludesNodeModules(t *testing.T) {
	excludes := DefaultExcludes()
	found := false
	for _, e := range excludes {
		if e == "node_modules" {
			found = true
			break
		}
	}
	assert.True(t, found, "must exclude node_modules")
}
