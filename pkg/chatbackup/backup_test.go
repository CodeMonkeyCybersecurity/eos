package chatbackup

import (
	"encoding/json"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ═══════════════════════════════════════════════════════════════════════════
// expandHome Tests
// ═══════════════════════════════════════════════════════════════════════════

func TestExpandHome_TildeSlash(t *testing.T) {
	result := expandHome("~/.claude/projects", "/home/testuser")
	assert.Equal(t, "/home/testuser/.claude/projects", result)
}

func TestExpandHome_TildeOnly(t *testing.T) {
	result := expandHome("~", "/home/testuser")
	assert.Equal(t, "/home/testuser", result)
}

func TestExpandHome_AbsolutePath(t *testing.T) {
	result := expandHome("/etc/config", "/home/testuser")
	assert.Equal(t, "/etc/config", result)
}

func TestExpandHome_RelativePath(t *testing.T) {
	result := expandHome("relative/path", "/home/testuser")
	assert.Equal(t, "relative/path", result)
}

func TestExpandHome_NestedTilde(t *testing.T) {
	result := expandHome("~/.config/Code/User/settings.json", "/home/testuser")
	assert.Equal(t, "/home/testuser/.config/Code/User/settings.json", result)
}

func TestExpandHome_EmptyHome(t *testing.T) {
	// With empty homeDir, filepath.Join("", "test") = "test"
	result := expandHome("~/test", "")
	assert.Equal(t, "test", result)
}

// ═══════════════════════════════════════════════════════════════════════════
// resolveHomeDir Tests
// ═══════════════════════════════════════════════════════════════════════════

func TestResolveHomeDir_Root(t *testing.T) {
	home, err := resolveHomeDir("root")
	require.NoError(t, err)
	assert.Equal(t, "/root", home)
}

func TestResolveHomeDir_Empty(t *testing.T) {
	// Empty username should resolve to current user's home
	home, err := resolveHomeDir("")
	require.NoError(t, err)
	assert.NotEmpty(t, home)
}

func TestResolveHomeDir_NonexistentUser(t *testing.T) {
	_, err := resolveHomeDir("nonexistent_user_xyz_12345")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "home directory not found")
}

func TestResolveBackupUsers_AllUsersFromPasswd(t *testing.T) {
	tmpDir := t.TempDir()
	homeDir := filepath.Join(tmpDir, "home", "henry")
	require.NoError(t, os.MkdirAll(homeDir, 0755))

	passwd := filepath.Join(tmpDir, "passwd")
	require.NoError(t, os.WriteFile(passwd, []byte(strings.Join([]string{
		"henry:x:1000:1000::" + homeDir + ":/bin/bash",
		"nobody:x:65534:65534::/nonexistent:/usr/sbin/nologin",
		"",
	}, "\n")), 0644))

	oldGeteuid := osGeteuid
	oldPasswd := passwdFilePath
	osGeteuid = func() int { return 0 }
	passwdFilePath = passwd
	t.Cleanup(func() {
		osGeteuid = oldGeteuid
		passwdFilePath = oldPasswd
	})

	users, err := resolveBackupUsers(BackupConfig{AllUsers: true})
	require.NoError(t, err)
	require.Len(t, users, 1)
	assert.Equal(t, "henry", users[0].Username)
	assert.Equal(t, homeDir, users[0].HomeDir)
}

func TestResolveStoragePaths_AllUsers(t *testing.T) {
	got, err := resolveStoragePaths(BackupConfig{AllUsers: true}, nil)
	require.NoError(t, err)
	assert.Equal(t, MachineRepoPath, got.Repo)
	assert.Equal(t, MachinePasswordFile, got.PasswordFile)
	assert.Equal(t, MachineStatusFile, got.StatusFile)
	assert.Equal(t, MachineManifestFile, got.ManifestFile)
	assert.Equal(t, MachineLockFile, got.LockFile)
}

// ═══════════════════════════════════════════════════════════════════════════
// discoverPaths Tests
// ═══════════════════════════════════════════════════════════════════════════

func TestDiscoverPaths_EmptyRegistry(t *testing.T) {
	logger := newSilentLogger()
	paths, tools, skipped := discoverPaths(logger, []ToolSource{}, "/tmp/nonexistent")
	assert.Empty(t, paths)
	assert.Empty(t, tools)
	assert.Empty(t, skipped)
}

func TestDiscoverPaths_NonexistentPaths(t *testing.T) {
	logger := newSilentLogger()
	registry := []ToolSource{
		{
			Name:        "test-tool",
			Description: "Test tool",
			Paths: []SourcePath{
				{
					Path:        "~/.nonexistent-tool/sessions",
					Description: "Sessions",
				},
			},
		},
	}

	paths, tools, skipped := discoverPaths(logger, registry, "/tmp/test-home-nonexistent")
	assert.Empty(t, paths, "should not include nonexistent paths")
	assert.Empty(t, tools, "should not report tool if no data found")
	assert.NotEmpty(t, skipped, "should report skipped paths")
}

func TestDiscoverPaths_ExistingDirectory(t *testing.T) {
	// Create a temporary directory structure simulating Claude Code data
	tmpDir := t.TempDir()
	claudeDir := filepath.Join(tmpDir, ".claude", "projects")
	require.NoError(t, os.MkdirAll(claudeDir, 0755))

	// Create a session file so the directory isn't empty
	testFile := filepath.Join(claudeDir, "test-session.jsonl")
	require.NoError(t, os.WriteFile(testFile, []byte(`{"test": true}`), 0644))

	logger := newSilentLogger()
	registry := []ToolSource{
		{
			Name:        "test-tool",
			Description: "Test tool",
			Paths: []SourcePath{
				{
					Path:        "~/.claude/projects",
					Description: "Projects",
				},
			},
		},
	}

	paths, tools, _ := discoverPaths(logger, registry, tmpDir)
	assert.Len(t, paths, 1, "should include existing directory")
	assert.Equal(t, claudeDir, paths[0])
	assert.Contains(t, tools, "test-tool")
}

func TestDiscoverPaths_EmptyDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	emptyDir := filepath.Join(tmpDir, ".claude", "empty")
	require.NoError(t, os.MkdirAll(emptyDir, 0755))

	logger := newSilentLogger()
	registry := []ToolSource{
		{
			Name:        "test-tool",
			Description: "Test tool",
			Paths: []SourcePath{
				{
					Path:        "~/.claude/empty",
					Description: "Empty dir",
				},
			},
		},
	}

	paths, tools, skipped := discoverPaths(logger, registry, tmpDir)
	assert.Empty(t, paths, "should not include empty directories")
	assert.Empty(t, tools)
	assert.NotEmpty(t, skipped, "empty dirs should be skipped")
}

func TestDiscoverPaths_FileNotDirectory(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a file (not directory)
	settingsFile := filepath.Join(tmpDir, ".claude", "settings.json")
	require.NoError(t, os.MkdirAll(filepath.Dir(settingsFile), 0755))
	require.NoError(t, os.WriteFile(settingsFile, []byte(`{}`), 0644))

	logger := newSilentLogger()
	registry := []ToolSource{
		{
			Name:        "test-tool",
			Description: "Test tool",
			Paths: []SourcePath{
				{
					Path:        "~/.claude/settings.json",
					Description: "Settings",
				},
			},
		},
	}

	paths, tools, _ := discoverPaths(logger, registry, tmpDir)
	assert.Len(t, paths, 1, "should include existing files")
	assert.Equal(t, settingsFile, paths[0])
	assert.Contains(t, tools, "test-tool")
}

func TestDiscoverPaths_Deduplication(t *testing.T) {
	tmpDir := t.TempDir()
	claudeDir := filepath.Join(tmpDir, ".claude", "projects")
	require.NoError(t, os.MkdirAll(claudeDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(claudeDir, "test.jsonl"), []byte(`{}`), 0644))

	logger := newSilentLogger()

	// Two tools referencing the same path
	registry := []ToolSource{
		{
			Name:        "tool-a",
			Description: "Tool A",
			Paths: []SourcePath{
				{Path: "~/.claude/projects", Description: "Projects"},
			},
		},
		{
			Name:        "tool-b",
			Description: "Tool B",
			Paths: []SourcePath{
				{Path: "~/.claude/projects", Description: "Also projects"},
			},
		},
	}

	paths, _, _ := discoverPaths(logger, registry, tmpDir)
	assert.Len(t, paths, 1, "should deduplicate identical paths")
}

func TestDiscoverPaths_MultipleTools(t *testing.T) {
	tmpDir := t.TempDir()

	// Create Claude data
	claudeDir := filepath.Join(tmpDir, ".claude", "projects")
	require.NoError(t, os.MkdirAll(claudeDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(claudeDir, "session.jsonl"), []byte(`{}`), 0644))

	// Create Codex data
	codexDir := filepath.Join(tmpDir, ".codex", "sessions")
	require.NoError(t, os.MkdirAll(codexDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(codexDir, "session.jsonl"), []byte(`{}`), 0644))

	logger := newSilentLogger()
	registry := []ToolSource{
		{
			Name:        "claude-code",
			Description: "Claude",
			Paths: []SourcePath{
				{Path: "~/.claude/projects", Description: "Projects"},
			},
		},
		{
			Name:        "codex",
			Description: "Codex",
			Paths: []SourcePath{
				{Path: "~/.codex/sessions", Description: "Sessions"},
			},
		},
	}

	paths, tools, _ := discoverPaths(logger, registry, tmpDir)
	assert.Len(t, paths, 2)
	assert.Contains(t, tools, "claude-code")
	assert.Contains(t, tools, "codex")
}

func TestDefaultToolRegistry_CoversHostMetadataPaths(t *testing.T) {
	registry := DefaultToolRegistry()

	assertToolPath := func(toolName, path string) {
		t.Helper()
		for _, tool := range registry {
			if tool.Name != toolName {
				continue
			}
			for _, sp := range tool.Paths {
				if sp.Path == path {
					return
				}
			}
		}
		t.Fatalf("expected %s to include path %s", toolName, path)
	}

	assertToolPath("codex", "~/.codex/auth.json")
	assertToolPath("codex", "~/.codex/session_index.jsonl")
	assertToolPath("windsurf", "~/.config/Windsurf/User")
	assert.Contains(t, DefaultExcludes(), ".claude/.credentials.json")
	assert.Contains(t, DefaultExcludes(), ".gemini/oauth_creds.json")
	assert.Contains(t, ProjectContextPatterns(), "MEMORY.md")
	assert.Contains(t, ProjectContextPatterns(), "memory.mds")
}

// ═══════════════════════════════════════════════════════════════════════════
// discoverProjectContext Tests
// ═══════════════════════════════════════════════════════════════════════════

func TestDiscoverProjectContext_EmptyScanDirs(t *testing.T) {
	logger := newSilentLogger()
	paths := discoverProjectContext(logger, []string{})
	assert.Empty(t, paths)
}

func TestDiscoverProjectContext_NonexistentDir(t *testing.T) {
	logger := newSilentLogger()
	paths := discoverProjectContext(logger, []string{"/tmp/nonexistent-xyz-12345"})
	assert.Empty(t, paths)
}

func TestDiscoverProjectContext_FindsClaudeMd(t *testing.T) {
	tmpDir := t.TempDir()
	projectDir := filepath.Join(tmpDir, "myproject")
	require.NoError(t, os.MkdirAll(projectDir, 0755))

	claudeMd := filepath.Join(projectDir, "CLAUDE.md")
	require.NoError(t, os.WriteFile(claudeMd, []byte("# Claude instructions"), 0644))

	logger := newSilentLogger()
	paths := discoverProjectContext(logger, []string{tmpDir})
	assert.Contains(t, paths, claudeMd)
}

func TestDiscoverProjectContext_FindsAgentsMd(t *testing.T) {
	tmpDir := t.TempDir()
	projectDir := filepath.Join(tmpDir, "myproject")
	require.NoError(t, os.MkdirAll(projectDir, 0755))

	agentsMd := filepath.Join(projectDir, "AGENTS.md")
	require.NoError(t, os.WriteFile(agentsMd, []byte("# Agents"), 0644))

	logger := newSilentLogger()
	paths := discoverProjectContext(logger, []string{tmpDir})
	assert.Contains(t, paths, agentsMd)
}

func TestDiscoverProjectContext_FindsClaudeDir(t *testing.T) {
	tmpDir := t.TempDir()
	projectDir := filepath.Join(tmpDir, "myproject", ".claude")
	require.NoError(t, os.MkdirAll(projectDir, 0755))

	logger := newSilentLogger()
	paths := discoverProjectContext(logger, []string{tmpDir})
	assert.Contains(t, paths, projectDir)
}

func TestDiscoverProjectContext_SkipsGitDir(t *testing.T) {
	tmpDir := t.TempDir()
	gitDir := filepath.Join(tmpDir, "myproject", ".git")
	require.NoError(t, os.MkdirAll(gitDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(gitDir, "CLAUDE.md"), []byte("# nope"), 0644))

	logger := newSilentLogger()
	paths := discoverProjectContext(logger, []string{tmpDir})
	// Should NOT find CLAUDE.md inside .git/
	for _, p := range paths {
		assert.NotContains(t, p, ".git",
			"should not include files inside .git/")
	}
}

func TestDiscoverProjectContext_SkipsNodeModules(t *testing.T) {
	tmpDir := t.TempDir()
	nmDir := filepath.Join(tmpDir, "myproject", "node_modules", "pkg")
	require.NoError(t, os.MkdirAll(nmDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(nmDir, "CLAUDE.md"), []byte("# nope"), 0644))

	logger := newSilentLogger()
	paths := discoverProjectContext(logger, []string{tmpDir})
	for _, p := range paths {
		assert.NotContains(t, p, "node_modules",
			"should not include files inside node_modules/")
	}
}

func TestDiscoverProjectContext_DepthLimit(t *testing.T) {
	tmpDir := t.TempDir()
	// Create deeply nested CLAUDE.md (depth 6 - should be excluded)
	deepDir := filepath.Join(tmpDir, "a", "b", "c", "d", "e")
	require.NoError(t, os.MkdirAll(deepDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(deepDir, "CLAUDE.md"), []byte("# deep"), 0644))

	// Create shallow CLAUDE.md (depth 1 - should be included)
	shallowDir := filepath.Join(tmpDir, "shallow")
	require.NoError(t, os.MkdirAll(shallowDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(shallowDir, "CLAUDE.md"), []byte("# shallow"), 0644))

	logger := newSilentLogger()
	paths := discoverProjectContext(logger, []string{tmpDir})

	shallowMd := filepath.Join(shallowDir, "CLAUDE.md")
	assert.Contains(t, paths, shallowMd, "should include shallow CLAUDE.md")
}

func TestDiscoverProjectContext_Deduplication(t *testing.T) {
	tmpDir := t.TempDir()
	projectDir := filepath.Join(tmpDir, "myproject")
	require.NoError(t, os.MkdirAll(projectDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(projectDir, "CLAUDE.md"), []byte("# Claude"), 0644))

	logger := newSilentLogger()
	// Scan the same dir twice
	paths := discoverProjectContext(logger, []string{tmpDir, tmpDir})

	// Count occurrences
	claudeMd := filepath.Join(projectDir, "CLAUDE.md")
	count := 0
	for _, p := range paths {
		if p == claudeMd {
			count++
		}
	}
	assert.Equal(t, 1, count, "should deduplicate paths across scan dirs")
}

// ═══════════════════════════════════════════════════════════════════════════
// updateStatus Tests
// ═══════════════════════════════════════════════════════════════════════════

func TestUpdateStatus_Success(t *testing.T) {
	tmpDir := t.TempDir()
	statusFile := filepath.Join(tmpDir, "status.json")
	logger := newSilentLogger()

	result := &BackupResult{
		SnapshotID: "abc123",
		BytesAdded: 1024,
	}

	updateStatus(logger, statusFile, backupStatusUpdate{
		Result:        result,
		ToolsFound:    []string{"claude-code"},
		PathsBackedUp: []string{"/tmp/fake"},
	}, "")

	// Read and verify
	data, err := os.ReadFile(statusFile)
	require.NoError(t, err)

	var status BackupStatus
	require.NoError(t, json.Unmarshal(data, &status))

	assert.NotEmpty(t, status.LastAttempt)
	assert.Equal(t, "success", status.LastRunState)
	assert.NotEmpty(t, status.LastSuccess)
	assert.Empty(t, status.LastError)
	assert.Equal(t, "abc123", status.LastSnapshotID)
	assert.Equal(t, int64(1024), status.BytesAdded)
	assert.Equal(t, 1, status.SuccessCount)
	assert.NotEmpty(t, status.FirstBackup)
	assert.Contains(t, status.ToolsFound, "claude-code")
	assert.Equal(t, 1, status.PathsBackedUpCount)
}

func TestUpdateStatus_Failure(t *testing.T) {
	tmpDir := t.TempDir()
	statusFile := filepath.Join(tmpDir, "status.json")
	logger := newSilentLogger()

	updateStatus(logger, statusFile, backupStatusUpdate{
		RunErr:     assert.AnError,
		ToolsFound: []string{"claude-code"},
	}, "")

	data, err := os.ReadFile(statusFile)
	require.NoError(t, err)

	var status BackupStatus
	require.NoError(t, json.Unmarshal(data, &status))

	assert.Equal(t, "failure", status.LastRunState)
	assert.NotEmpty(t, status.LastFailure)
	assert.Contains(t, status.LastError, "assert.AnError")
	assert.Equal(t, 1, status.FailureCount)
	assert.Empty(t, status.LastSuccess, "success should not be set on failure")
}

func TestUpdateStatus_IncrementalCounts(t *testing.T) {
	tmpDir := t.TempDir()
	statusFile := filepath.Join(tmpDir, "status.json")
	logger := newSilentLogger()

	// Two successes then a failure
	result := &BackupResult{SnapshotID: "snap1"}
	updateStatus(logger, statusFile, backupStatusUpdate{Result: result}, "")
	result2 := &BackupResult{SnapshotID: "snap2"}
	updateStatus(logger, statusFile, backupStatusUpdate{Result: result2}, "")
	updateStatus(logger, statusFile, backupStatusUpdate{RunErr: assert.AnError}, "") // failure

	data, err := os.ReadFile(statusFile)
	require.NoError(t, err)

	var status BackupStatus
	require.NoError(t, json.Unmarshal(data, &status))

	assert.Equal(t, 2, status.SuccessCount)
	assert.Equal(t, 1, status.FailureCount)
	assert.Equal(t, "failure", status.LastRunState)
	assert.Equal(t, "snap2", status.LastSnapshotID)
}

func TestUpdateStatus_PreservesFirstBackup(t *testing.T) {
	tmpDir := t.TempDir()
	statusFile := filepath.Join(tmpDir, "status.json")
	logger := newSilentLogger()

	result := &BackupResult{SnapshotID: "first"}
	updateStatus(logger, statusFile, backupStatusUpdate{Result: result}, "")

	data, err := os.ReadFile(statusFile)
	require.NoError(t, err)
	var status1 BackupStatus
	require.NoError(t, json.Unmarshal(data, &status1))
	firstBackup := status1.FirstBackup

	// Second backup should NOT overwrite FirstBackup
	result2 := &BackupResult{SnapshotID: "second"}
	updateStatus(logger, statusFile, backupStatusUpdate{Result: result2}, "")

	data2, err := os.ReadFile(statusFile)
	require.NoError(t, err)
	var status2 BackupStatus
	require.NoError(t, json.Unmarshal(data2, &status2))

	assert.Equal(t, firstBackup, status2.FirstBackup,
		"first backup timestamp should be preserved")
}

func TestUpdateStatus_NoopClearsLastErrorWithoutChangingCounters(t *testing.T) {
	tmpDir := t.TempDir()
	statusFile := filepath.Join(tmpDir, "status.json")
	logger := newSilentLogger()

	updateStatus(logger, statusFile, backupStatusUpdate{
		RunErr:     assert.AnError,
		ToolsFound: []string{"claude-code"},
	}, "")
	updateStatus(logger, statusFile, backupStatusUpdate{
		ToolsFound:   []string{"claude-code"},
		UsersScanned: []string{"henry"},
	}, "")

	data, err := os.ReadFile(statusFile)
	require.NoError(t, err)

	var status BackupStatus
	require.NoError(t, json.Unmarshal(data, &status))

	assert.Equal(t, "noop", status.LastRunState)
	assert.Empty(t, status.LastError)
	assert.Equal(t, 0, status.SuccessCount)
	assert.Equal(t, 1, status.FailureCount)
	assert.Equal(t, []string{"henry"}, status.UsersScanned)
}

func TestUpdateStatus_CorruptExistingFileStartsFresh(t *testing.T) {
	tmpDir := t.TempDir()
	statusFile := filepath.Join(tmpDir, "status.json")
	require.NoError(t, os.WriteFile(statusFile, []byte("{not-json"), 0600))

	updateStatus(newSilentLogger(), statusFile, backupStatusUpdate{
		Result:        &BackupResult{SnapshotID: "snap-1"},
		PathsBackedUp: []string{"/tmp/fake"},
	}, "")

	data, err := os.ReadFile(statusFile)
	require.NoError(t, err)

	var status BackupStatus
	require.NoError(t, json.Unmarshal(data, &status))
	assert.Equal(t, "success", status.LastRunState)
	assert.Equal(t, "snap-1", status.LastSnapshotID)
	assert.Equal(t, 1, status.SuccessCount)
}

func TestWriteManifest_Success(t *testing.T) {
	tmpDir := t.TempDir()
	manifestFile := filepath.Join(tmpDir, "manifest.json")

	writeManifest(newSilentLogger(), manifestFile, &BackupResult{
		SnapshotID:    "snap-1",
		UsersScanned:  []string{"henry"},
		ToolsFound:    []string{"claude-code"},
		PathsBackedUp: []string{"/tmp/project"},
		PathsSkipped:  []string{"/tmp/missing"},
	}, "")

	data, err := os.ReadFile(manifestFile)
	require.NoError(t, err)

	var manifest BackupManifest
	require.NoError(t, json.Unmarshal(data, &manifest))
	assert.Equal(t, "snap-1", manifest.SnapshotID)
	assert.Equal(t, []string{"henry"}, manifest.UsersScanned)
	assert.Equal(t, []string{"/tmp/project"}, manifest.PathsIncluded)
	assert.Equal(t, []string{"/tmp/missing"}, manifest.PathsSkipped)
}

func TestWriteManifest_SkipWhenSnapshotMissing(t *testing.T) {
	manifestFile := filepath.Join(t.TempDir(), "manifest.json")
	writeManifest(newSilentLogger(), manifestFile, &BackupResult{}, "")
	_, err := os.Stat(manifestFile)
	assert.Error(t, err)
}

func TestWriteManifest_DirectoryCreationFailure(t *testing.T) {
	tmpDir := t.TempDir()
	parentFile := filepath.Join(tmpDir, "not-a-dir")
	require.NoError(t, os.WriteFile(parentFile, []byte("x"), 0600))

	writeManifest(newSilentLogger(), filepath.Join(parentFile, "manifest.json"), &BackupResult{
		SnapshotID: "snap-1",
	}, "")
}

func TestWriteManifest_RenameFailure(t *testing.T) {
	tmpDir := t.TempDir()
	manifestTarget := filepath.Join(tmpDir, "manifest-target")
	require.NoError(t, os.MkdirAll(manifestTarget, 0700))

	writeManifest(newSilentLogger(), manifestTarget, &BackupResult{
		SnapshotID: "snap-1",
	}, "")
}

func TestWriteManifest_EnsuresOwnership(t *testing.T) {
	manifestFile := filepath.Join(t.TempDir(), "manifest.json")

	oldGeteuid := osGeteuid
	oldLookup := userLookup
	oldChown := osChown
	osGeteuid = func() int { return 0 }
	userLookup = func(string) (*user.User, error) {
		return &user.User{Uid: "1001", Gid: "1002"}, nil
	}
	called := false
	osChown = func(path string, uid, gid int) error {
		called = true
		assert.Equal(t, manifestFile, path)
		return nil
	}
	t.Cleanup(func() {
		osGeteuid = oldGeteuid
		userLookup = oldLookup
		osChown = oldChown
	})

	writeManifest(newSilentLogger(), manifestFile, &BackupResult{SnapshotID: "snap-1"}, "henry")
	assert.True(t, called)
}

func TestPersistBackupRun_WritesManifestOnSuccess(t *testing.T) {
	tmpDir := t.TempDir()
	paths := storagePaths{
		StatusFile:   filepath.Join(tmpDir, "status.json"),
		ManifestFile: filepath.Join(tmpDir, "manifest.json"),
	}

	persistBackupRun(newSilentLogger(), paths, "", backupStatusUpdate{
		Result: &BackupResult{
			SnapshotID:    "snap-2",
			UsersScanned:  []string{"henry"},
			ToolsFound:    []string{"claude-code"},
			PathsBackedUp: []string{"/tmp/project"},
		},
		ToolsFound:    []string{"claude-code"},
		UsersScanned:  []string{"henry"},
		PathsBackedUp: []string{"/tmp/project"},
	})

	_, statusErr := os.Stat(paths.StatusFile)
	require.NoError(t, statusErr)
	_, manifestErr := os.Stat(paths.ManifestFile)
	require.NoError(t, manifestErr)
}

func TestPersistBackupRun_SkipsManifestOnFailure(t *testing.T) {
	tmpDir := t.TempDir()
	paths := storagePaths{
		StatusFile:   filepath.Join(tmpDir, "status.json"),
		ManifestFile: filepath.Join(tmpDir, "manifest.json"),
	}

	persistBackupRun(newSilentLogger(), paths, "", backupStatusUpdate{
		RunErr:        assert.AnError,
		ToolsFound:    []string{"claude-code"},
		UsersScanned:  []string{"henry"},
		PathsBackedUp: []string{"/tmp/project"},
	})

	_, statusErr := os.Stat(paths.StatusFile)
	require.NoError(t, statusErr)
	_, manifestErr := os.Stat(paths.ManifestFile)
	assert.Error(t, manifestErr)
}

func TestPersistBackupRun_NoStatusPathIsNoop(t *testing.T) {
	persistBackupRun(newSilentLogger(), storagePaths{}, "", backupStatusUpdate{
		Result: &BackupResult{SnapshotID: "snap-3"},
	})
}

func TestNormalizeScanDirs_DefaultSingleUser(t *testing.T) {
	assert.Equal(t, []string{"/opt"}, normalizeScanDirs(BackupConfig{}, []scannedUser{{Username: "henry", HomeDir: "/home/henry"}}))
}

func TestResolveStoragePaths_SingleUser(t *testing.T) {
	got, err := resolveStoragePaths(BackupConfig{}, []scannedUser{{Username: "henry", HomeDir: "/home/henry"}})
	require.NoError(t, err)
	assert.Equal(t, "/home/henry/"+ResticRepoSubdir, got.Repo)
	assert.Equal(t, "/home/henry/"+ResticManifestSubdir, got.ManifestFile)
}

func TestNormalizeScanDirs_AllUsersIncludesHomes(t *testing.T) {
	got := normalizeScanDirs(BackupConfig{AllUsers: true}, []scannedUser{
		{Username: "alice", HomeDir: "/home/alice"},
		{Username: "bob", HomeDir: "/srv/bob"},
	})
	assert.Equal(t, []string{DefaultHomeScanDir, "/home/alice", "/opt", "/srv/bob"}, got)
}

func TestNormalizeScanDirs_ExplicitOverrideWins(t *testing.T) {
	got := normalizeScanDirs(BackupConfig{
		AllUsers:      true,
		ExtraScanDirs: []string{"/srv", "/srv", "/opt/custom"},
	}, nil)
	assert.Equal(t, []string{DefaultHomeScanDir, "/opt/custom", "/srv"}, got)
}

func TestOwnershipUser(t *testing.T) {
	oldGeteuid := osGeteuid
	osGeteuid = func() int { return 0 }
	t.Cleanup(func() {
		osGeteuid = oldGeteuid
	})

	assert.Equal(t, "henry", ownershipUser(BackupConfig{User: "henry"}))
	assert.Empty(t, ownershipUser(BackupConfig{AllUsers: true, User: "henry"}))
	assert.Empty(t, ownershipUser(BackupConfig{User: RootUsername}))
	assert.Empty(t, ownershipUser(BackupConfig{}))
}

func TestEnsureOwnership_NoopBranches(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "status.json")
	require.NoError(t, os.WriteFile(tmpFile, []byte("{}"), 0600))

	require.NoError(t, ensureOwnership(tmpFile, ""))

	oldGeteuid := osGeteuid
	osGeteuid = func() int { return 1000 }
	t.Cleanup(func() {
		osGeteuid = oldGeteuid
	})

	require.NoError(t, ensureOwnership(tmpFile, "henry"))
}

func TestAcquireBackupLock_SetsOwnershipForDelegatedUser(t *testing.T) {
	lockFile := filepath.Join(t.TempDir(), "chatbackup.lock")

	oldGeteuid := osGeteuid
	oldLookup := userLookup
	oldChown := osChown
	osGeteuid = func() int { return 0 }
	userLookup = func(string) (*user.User, error) {
		return &user.User{Uid: "1001", Gid: "1002"}, nil
	}
	called := false
	osChown = func(path string, uid, gid int) error {
		called = true
		assert.Equal(t, lockFile, path)
		assert.Equal(t, 1001, uid)
		assert.Equal(t, 1002, gid)
		return nil
	}
	t.Cleanup(func() {
		osGeteuid = oldGeteuid
		userLookup = oldLookup
		osChown = oldChown
	})

	lock, err := acquireBackupLock(lockFile, "henry")
	require.NoError(t, err)
	assert.True(t, called)
	releaseBackupLock(lock)
}

func TestParseID(t *testing.T) {
	id, err := parseID("42")
	require.NoError(t, err)
	assert.Equal(t, 42, id)

	_, err = parseID("not-a-number")
	require.Error(t, err)
}

func TestCompactError(t *testing.T) {
	assert.Empty(t, compactError(nil))
	longMessage := strings.Repeat("word ", 80)
	assert.Equal(t, assert.AnError.Error(), compactError(assert.AnError))

	truncated := compactError(errors.New(longMessage))
	assert.LessOrEqual(t, len(truncated), 240)
	assert.True(t, strings.HasSuffix(truncated, "..."))
}
