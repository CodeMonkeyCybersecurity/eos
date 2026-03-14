package backup

import (
	"context"
	"os"
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/chats"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newChatsTestCommand(t *testing.T) *cobra.Command {
	t.Helper()
	cmd := &cobra.Command{Use: "chats"}
	cmd.Flags().Bool("dry-run", false, "")
	return cmd
}

func newChatsRuntimeContext() *eos_io.RuntimeContext {
	return eos_io.NewContext(context.Background(), "chats-test")
}

func resetChatBackupFn(t *testing.T) {
	t.Helper()
	orig := chatBackupFn
	t.Cleanup(func() { chatBackupFn = orig })
}

func TestRunBackupChats_CallsBusinessLogic(t *testing.T) {
	resetChatBackupFn(t)
	cmd := newChatsTestCommand(t)

	called := false
	chatBackupFn = func(rc *eos_io.RuntimeContext, config chats.BackupConfig) (*chats.BackupResult, error) {
		called = true
		assert.NotEmpty(t, config.HomeDir)
		assert.NotEmpty(t, config.ConfigDir)
		assert.NotEmpty(t, config.RepoRoot)
		assert.False(t, config.DryRun)
		return &chats.BackupResult{SourcesFound: 2, NewFiles: 5}, nil
	}

	err := runBackupChats(newChatsRuntimeContext(), cmd, nil)
	require.NoError(t, err)
	assert.True(t, called)
}

func TestRunBackupChats_DryRunFlag(t *testing.T) {
	resetChatBackupFn(t)
	cmd := newChatsTestCommand(t)
	require.NoError(t, cmd.Flags().Set("dry-run", "true"))

	chatBackupFn = func(rc *eos_io.RuntimeContext, config chats.BackupConfig) (*chats.BackupResult, error) {
		assert.True(t, config.DryRun)
		return &chats.BackupResult{NewFiles: 3}, nil
	}

	err := runBackupChats(newChatsRuntimeContext(), cmd, nil)
	require.NoError(t, err)
}

func TestRunBackupChats_FlagLikeArgsRejected(t *testing.T) {
	resetChatBackupFn(t)
	cmd := newChatsTestCommand(t)

	err := runBackupChats(newChatsRuntimeContext(), cmd, []string{"--force"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "flag")
}

func TestRunBackupChats_BusinessLogicError(t *testing.T) {
	resetChatBackupFn(t)
	cmd := newChatsTestCommand(t)

	chatBackupFn = func(rc *eos_io.RuntimeContext, config chats.BackupConfig) (*chats.BackupResult, error) {
		return nil, assert.AnError
	}

	err := runBackupChats(newChatsRuntimeContext(), cmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "chat backup failed")
}

func TestResolveRepoRoot_FromEnv(t *testing.T) {
	old, had := os.LookupEnv("CLAUDE_PROJECT_DIR")
	require.NoError(t, os.Setenv("CLAUDE_PROJECT_DIR", "/tmp/test-repo"))
	t.Cleanup(func() {
		if had {
			_ = os.Setenv("CLAUDE_PROJECT_DIR", old)
		} else {
			_ = os.Unsetenv("CLAUDE_PROJECT_DIR")
		}
	})

	root, err := resolveRepoRoot()
	require.NoError(t, err)
	assert.Equal(t, "/tmp/test-repo", root)
}

func TestResolveRepoRoot_FallsBackToGitOrCwd(t *testing.T) {
	old, had := os.LookupEnv("CLAUDE_PROJECT_DIR")
	_ = os.Unsetenv("CLAUDE_PROJECT_DIR")
	t.Cleanup(func() {
		if had {
			_ = os.Setenv("CLAUDE_PROJECT_DIR", old)
		}
	})

	root, err := resolveRepoRoot()
	require.NoError(t, err)
	assert.NotEmpty(t, root)
}
