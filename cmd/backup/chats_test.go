package backup

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/chatbackup"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
)

func newChatsTestCommand(t *testing.T) *cobra.Command {
	t.Helper()

	cmd := &cobra.Command{Use: "chats"}
	cmd.Flags().Bool("setup", false, "")
	cmd.Flags().Bool("prune", false, "")
	cmd.Flags().Bool("list", false, "")
	cmd.Flags().Bool("dry-run", false, "")
	cmd.Flags().String("user", "", "")
	cmd.Flags().Bool("all-users", false, "")
	cmd.Flags().StringSlice("scan-dirs", []string{"/opt"}, "")
	cmd.Flags().Bool("verbose", false, "")
	cmd.Flags().String("keep-within", chatbackup.DefaultKeepWithin, "")
	cmd.Flags().Int("keep-hourly", chatbackup.DefaultKeepHourly, "")
	cmd.Flags().Int("keep-daily", chatbackup.DefaultKeepDaily, "")
	cmd.Flags().Int("keep-weekly", chatbackup.DefaultKeepWeekly, "")
	cmd.Flags().Int("keep-monthly", chatbackup.DefaultKeepMonthly, "")
	cmd.Flags().String("backup-cron", chatbackup.DefaultBackupCron, "")
	cmd.Flags().String("prune-cron", chatbackup.DefaultPruneCron, "")
	return cmd
}

func newChatsRuntimeContext() *eos_io.RuntimeContext {
	return eos_io.NewContext(context.Background(), "chats-test")
}

func resetChatbackupFns(t *testing.T) {
	t.Helper()

	origRunBackup := chatbackupRunBackupFn
	origSetup := chatbackupSetupFn
	origRunPrune := chatbackupRunPruneFn
	origList := chatbackupListSnapshotsFn

	t.Cleanup(func() {
		chatbackupRunBackupFn = origRunBackup
		chatbackupSetupFn = origSetup
		chatbackupRunPruneFn = origRunPrune
		chatbackupListSnapshotsFn = origList
	})
}

func TestResolveCurrentUser_PrefersSudoUser(t *testing.T) {
	old, had := os.LookupEnv("SUDO_USER")
	require.NoError(t, os.Setenv("SUDO_USER", "henry"))
	t.Cleanup(func() {
		if had {
			_ = os.Setenv("SUDO_USER", old)
			return
		}
		_ = os.Unsetenv("SUDO_USER")
	})

	assert.Equal(t, "henry", resolveCurrentUser())
}

func TestResolveCurrentUser_CurrentUserFallback(t *testing.T) {
	old, had := os.LookupEnv("SUDO_USER")
	_ = os.Unsetenv("SUDO_USER")
	t.Cleanup(func() {
		if had {
			_ = os.Setenv("SUDO_USER", old)
			return
		}
		_ = os.Unsetenv("SUDO_USER")
	})

	assert.NotEmpty(t, resolveCurrentUser())
}

func TestValidateModeFlags(t *testing.T) {
	require.NoError(t, validateModeFlags(false, false, false, false))
	require.NoError(t, validateModeFlags(true, false, false, false))
	require.NoError(t, validateModeFlags(false, true, false, false))
	require.NoError(t, validateModeFlags(false, false, true, false))

	err := validateModeFlags(true, true, false, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mutually exclusive")

	err = validateModeFlags(false, false, true, true)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--dry-run cannot be combined with --list")
}

func TestParseRetentionPolicy(t *testing.T) {
	cmd := newChatsTestCommand(t)
	require.NoError(t, cmd.Flags().Set("keep-within", "72h"))
	require.NoError(t, cmd.Flags().Set("keep-daily", "10"))

	got, err := parseRetentionPolicy(cmd)
	require.NoError(t, err)
	assert.Equal(t, "72h", got.KeepWithin)
	assert.Equal(t, 10, got.KeepDaily)
	assert.Equal(t, chatbackup.DefaultKeepHourly, got.KeepHourly)
}

func TestParseRetentionPolicy_AllOverrides(t *testing.T) {
	cmd := newChatsTestCommand(t)
	require.NoError(t, cmd.Flags().Set("keep-within", "24h"))
	require.NoError(t, cmd.Flags().Set("keep-hourly", "12"))
	require.NoError(t, cmd.Flags().Set("keep-daily", "3"))
	require.NoError(t, cmd.Flags().Set("keep-weekly", "2"))
	require.NoError(t, cmd.Flags().Set("keep-monthly", "6"))

	got, err := parseRetentionPolicy(cmd)
	require.NoError(t, err)
	assert.Equal(t, "24h", got.KeepWithin)
	assert.Equal(t, 12, got.KeepHourly)
	assert.Equal(t, 3, got.KeepDaily)
	assert.Equal(t, 2, got.KeepWeekly)
	assert.Equal(t, 6, got.KeepMonthly)
}

func TestParseRetentionPolicy_TypeError(t *testing.T) {
	cmd := &cobra.Command{Use: "chats"}
	cmd.Flags().String("keep-within", chatbackup.DefaultKeepWithin, "")
	cmd.Flags().String("keep-hourly", "24", "")
	require.NoError(t, cmd.Flags().Set("keep-hourly", "oops"))

	_, err := parseRetentionPolicy(cmd)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "int")
}

func TestRunBackupChats_RoutesSetup(t *testing.T) {
	resetChatbackupFns(t)
	cmd := newChatsTestCommand(t)
	require.NoError(t, cmd.Flags().Set("setup", "true"))
	require.NoError(t, cmd.Flags().Set("user", "henry"))

	setupCalled := false
	chatbackupSetupFn = func(rc *eos_io.RuntimeContext, config chatbackup.ScheduleConfig) (*chatbackup.ScheduleResult, error) {
		setupCalled = true
		assert.Equal(t, "henry", config.User)
		return &chatbackup.ScheduleResult{RepoPath: "/tmp/repo", PasswordFile: "/tmp/pw"}, nil
	}
	chatbackupRunBackupFn = func(*eos_io.RuntimeContext, chatbackup.BackupConfig) (*chatbackup.BackupResult, error) {
		return nil, fmt.Errorf("unexpected backup path")
	}

	err := runBackupChats(newChatsRuntimeContext(), cmd, nil)
	require.NoError(t, err)
	assert.True(t, setupCalled)
}

func TestRunBackupChats_MissingFlagsError(t *testing.T) {
	resetChatbackupFns(t)
	cmd := &cobra.Command{Use: "chats"}
	cmd.Flags().Bool("all-users", false, "")
	err := runBackupChats(newChatsRuntimeContext(), cmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "dry-run")
}

func TestRunBackupChats_RoutesPrune(t *testing.T) {
	resetChatbackupFns(t)
	cmd := newChatsTestCommand(t)
	require.NoError(t, cmd.Flags().Set("prune", "true"))
	require.NoError(t, cmd.Flags().Set("user", "henry"))

	pruneCalled := false
	chatbackupRunPruneFn = func(rc *eos_io.RuntimeContext, config chatbackup.BackupConfig) error {
		pruneCalled = true
		assert.Equal(t, "henry", config.User)
		return nil
	}

	err := runBackupChats(newChatsRuntimeContext(), cmd, nil)
	require.NoError(t, err)
	assert.True(t, pruneCalled)
}

func TestRunBackupChats_RoutesList(t *testing.T) {
	resetChatbackupFns(t)
	cmd := newChatsTestCommand(t)
	require.NoError(t, cmd.Flags().Set("list", "true"))
	require.NoError(t, cmd.Flags().Set("user", "henry"))

	listCalled := false
	chatbackupListSnapshotsFn = func(rc *eos_io.RuntimeContext, config chatbackup.BackupConfig) (string, error) {
		listCalled = true
		assert.Equal(t, "henry", config.User)
		return "ID  Time\n", nil
	}

	err := runBackupChats(newChatsRuntimeContext(), cmd, nil)
	require.NoError(t, err)
	assert.True(t, listCalled)
}

func TestRunBackupChats_RoutesBackup(t *testing.T) {
	resetChatbackupFns(t)
	cmd := newChatsTestCommand(t)
	require.NoError(t, cmd.Flags().Set("user", "henry"))
	require.NoError(t, cmd.Flags().Set("scan-dirs", "/opt,/srv"))
	require.NoError(t, cmd.Flags().Set("verbose", "true"))

	backupCalled := false
	chatbackupRunBackupFn = func(rc *eos_io.RuntimeContext, config chatbackup.BackupConfig) (*chatbackup.BackupResult, error) {
		backupCalled = true
		assert.Equal(t, "henry", config.User)
		assert.Equal(t, []string{"/opt", "/srv"}, config.ExtraScanDirs)
		assert.True(t, config.Verbose)
		return &chatbackup.BackupResult{}, nil
	}

	err := runBackupChats(newChatsRuntimeContext(), cmd, nil)
	require.NoError(t, err)
	assert.True(t, backupCalled)
}

func TestRunBackupChats_ValidationError(t *testing.T) {
	resetChatbackupFns(t)
	cmd := newChatsTestCommand(t)
	require.NoError(t, cmd.Flags().Set("setup", "true"))
	require.NoError(t, cmd.Flags().Set("prune", "true"))

	err := runBackupChats(newChatsRuntimeContext(), cmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mutually exclusive")
}

func TestRunBackupChats_AllUsersRequiresRoot(t *testing.T) {
	resetChatbackupFns(t)
	cmd := newChatsTestCommand(t)
	require.NoError(t, cmd.Flags().Set("all-users", "true"))

	err := runBackupChats(newChatsRuntimeContext(), cmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "requires root")
}

func TestRunBackupChats_MapDependencyError(t *testing.T) {
	resetChatbackupFns(t)
	cmd := newChatsTestCommand(t)
	require.NoError(t, cmd.Flags().Set("user", "henry"))

	chatbackupRunBackupFn = func(*eos_io.RuntimeContext, chatbackup.BackupConfig) (*chatbackup.BackupResult, error) {
		return nil, fmt.Errorf("wrapped: %w", chatbackup.ErrResticNotInstalled)
	}

	err := runBackupChats(newChatsRuntimeContext(), cmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "restic")
	assert.Equal(t, 1, eos_err.GetExitCode(err))
}

func TestRunBackupChats_MapRepoInitializationError(t *testing.T) {
	resetChatbackupFns(t)
	cmd := newChatsTestCommand(t)
	require.NoError(t, cmd.Flags().Set("user", "henry"))

	chatbackupRunBackupFn = func(*eos_io.RuntimeContext, chatbackup.BackupConfig) (*chatbackup.BackupResult, error) {
		return nil, fmt.Errorf("wrapped: %w", chatbackup.ErrRepositoryNotInitialized)
	}

	err := runBackupChats(newChatsRuntimeContext(), cmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--setup")
	assert.Equal(t, 1, eos_err.GetExitCode(err))
}

func TestMapChatbackupError_UnknownPassThrough(t *testing.T) {
	err := mapChatbackupError(newChatsRuntimeContext(), "backup", errors.New("boom"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "backup failed: boom")
}

func TestMapChatbackupError_BackupAlreadyRunning(t *testing.T) {
	err := mapChatbackupError(newChatsRuntimeContext(), "backup", chatbackup.ErrBackupAlreadyRunning)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "currently running")
}

func TestMapChatbackupError_Nil(t *testing.T) {
	assert.NoError(t, mapChatbackupError(newChatsRuntimeContext(), "backup", nil))
}

func TestFormatResult(t *testing.T) {
	out := FormatResult(&chatbackup.BackupResult{
		SnapshotID:      "abc123",
		TotalDuration:   "1.0s",
		FilesNew:        1,
		FilesChanged:    2,
		FilesUnmodified: 3,
		BytesAdded:      42,
		ToolsFound:      []string{"codex", "claude-code"},
	})

	assert.Contains(t, out, "abc123")
	assert.Contains(t, out, "Files: 1 new, 2 changed, 3 unmodified")
	assert.Contains(t, out, "Tools: codex, claude-code")
}

func TestRunSetup_MapsErrors(t *testing.T) {
	resetChatbackupFns(t)
	cmd := newChatsTestCommand(t)
	logger := otelzap.Ctx(newChatsRuntimeContext().Ctx)

	chatbackupSetupFn = func(*eos_io.RuntimeContext, chatbackup.ScheduleConfig) (*chatbackup.ScheduleResult, error) {
		return nil, fmt.Errorf("wrapped: %w", chatbackup.ErrResticNotInstalled)
	}

	err := runSetup(newChatsRuntimeContext(), logger, cmd, "henry", false, chatbackup.DefaultRetentionPolicy(), false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "restic")
}

func TestRunSetup_MissingCronFlagsError(t *testing.T) {
	resetChatbackupFns(t)
	cmd := &cobra.Command{Use: "chats"}
	logger := otelzap.Ctx(newChatsRuntimeContext().Ctx)

	err := runSetup(newChatsRuntimeContext(), logger, cmd, "henry", false, chatbackup.DefaultRetentionPolicy(), false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "backup-cron")
}

func TestRunPrune_MapsErrors(t *testing.T) {
	resetChatbackupFns(t)
	logger := otelzap.Ctx(newChatsRuntimeContext().Ctx)
	chatbackupRunPruneFn = func(*eos_io.RuntimeContext, chatbackup.BackupConfig) error {
		return fmt.Errorf("wrapped: %w", chatbackup.ErrRepositoryNotInitialized)
	}

	err := runPrune(newChatsRuntimeContext(), logger, "henry", false, chatbackup.DefaultRetentionPolicy(), false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--setup")
}

func TestRunList_MapsErrors(t *testing.T) {
	resetChatbackupFns(t)
	logger := otelzap.Ctx(newChatsRuntimeContext().Ctx)
	chatbackupListSnapshotsFn = func(*eos_io.RuntimeContext, chatbackup.BackupConfig) (string, error) {
		return "", fmt.Errorf("wrapped: %w", chatbackup.ErrResticNotInstalled)
	}

	err := runList(newChatsRuntimeContext(), logger, "henry", false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "restic")
}

func TestRunBackup_NoDataLogsAndSucceeds(t *testing.T) {
	resetChatbackupFns(t)
	logger := otelzap.Ctx(newChatsRuntimeContext().Ctx)
	chatbackupRunBackupFn = func(*eos_io.RuntimeContext, chatbackup.BackupConfig) (*chatbackup.BackupResult, error) {
		return &chatbackup.BackupResult{}, nil
	}

	err := runBackup(newChatsRuntimeContext(), logger, "henry", false, chatbackup.DefaultRetentionPolicy(), []string{"/opt"}, false, false)
	require.NoError(t, err)
}

func TestRunBackup_DryRunBranch(t *testing.T) {
	resetChatbackupFns(t)
	logger := otelzap.Ctx(newChatsRuntimeContext().Ctx)
	chatbackupRunBackupFn = func(*eos_io.RuntimeContext, chatbackup.BackupConfig) (*chatbackup.BackupResult, error) {
		return &chatbackup.BackupResult{
			ToolsFound:    []string{"codex"},
			PathsBackedUp: []string{"/tmp/path"},
			PathsSkipped:  []string{"/tmp/missing"},
		}, nil
	}

	err := runBackup(newChatsRuntimeContext(), logger, "henry", false, chatbackup.DefaultRetentionPolicy(), []string{"/opt"}, true, false)
	require.NoError(t, err)
}
