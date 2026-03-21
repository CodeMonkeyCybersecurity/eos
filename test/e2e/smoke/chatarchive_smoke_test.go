//go:build e2e_smoke

package smoke

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/test/e2e"
	"github.com/stretchr/testify/require"
)

func TestSmoke_ChatArchiveHelp(t *testing.T) {
	suite := e2e.NewE2ETestSuite(t, "chat-archive-help")

	t.Run("CreateCommandExists", func(t *testing.T) {
		result := suite.RunCommand("create", "chat-archive", "--help")
		result.AssertSuccess(t)
		result.AssertContains(t, "Find transcript-like files")
		result.AssertContains(t, "eos create chat-archive")
	})

	t.Run("BackupAliasExists", func(t *testing.T) {
		result := suite.RunCommand("backup", "chats", "--help")
		result.AssertSuccess(t)
		result.AssertContains(t, "convenience alias")
		result.AssertContains(t, "eos backup chats")
	})
}

func TestSmoke_ChatArchiveDryRun(t *testing.T) {
	suite := e2e.NewE2ETestSuite(t, "chat-archive-dry-run")

	srcDir := filepath.Join(suite.WorkDir, "source")
	destDir := filepath.Join(suite.WorkDir, "archive")
	require.NoError(t, os.MkdirAll(filepath.Join(srcDir, "sessions"), 0755))
	require.NoError(t, os.WriteFile(
		filepath.Join(srcDir, "sessions", "chat.jsonl"),
		[]byte(`{"role":"user","content":"hello"}`), 0644))

	result := suite.RunCommand("create", "chat-archive", "--source", srcDir, "--dest", destDir, "--dry-run")
	result.AssertSuccess(t)
	result.AssertContains(t, "Dry run complete.")
	result.AssertContains(t, "Unique files: 1")

	_, err := os.Stat(destDir)
	require.True(t, os.IsNotExist(err), "dry-run should not create destination directory")
}

func TestSmoke_BackupChatsWritesManifest(t *testing.T) {
	suite := e2e.NewE2ETestSuite(t, "backup-chats-run")

	srcDir := filepath.Join(suite.WorkDir, "source")
	destDir := filepath.Join(suite.WorkDir, "archive")
	require.NoError(t, os.MkdirAll(filepath.Join(srcDir, "sessions"), 0755))
	require.NoError(t, os.WriteFile(
		filepath.Join(srcDir, "sessions", "chat.jsonl"),
		[]byte(`{"role":"assistant","content":"stored"}`), 0644))

	result := suite.RunCommand("backup", "chats", "--source", srcDir, "--dest", destDir)
	result.AssertSuccess(t)
	result.AssertContains(t, "Archive complete.")
	result.AssertContains(t, "Manifest:")

	_, err := os.Stat(filepath.Join(destDir, "manifest.json"))
	require.NoError(t, err)
}
