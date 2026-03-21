package chatbackup

import (
	"context"
	"encoding/json"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newRuntimeContext() *eos_io.RuntimeContext {
	return eos_io.NewContext(context.Background(), "chatbackup-test")
}

func prependFakeBin(t *testing.T, binaries map[string]string) {
	t.Helper()

	tmp := t.TempDir()
	for name, body := range binaries {
		path := filepath.Join(tmp, name)
		require.NoError(t, os.WriteFile(path, []byte(body), 0755))
	}

	oldPath := os.Getenv("PATH")
	require.NoError(t, os.Setenv("PATH", tmp+string(os.PathListSeparator)+oldPath))
	t.Cleanup(func() {
		_ = os.Setenv("PATH", oldPath)
	})
}

func fakeResticScript() string {
	return `#!/usr/bin/env bash
set -euo pipefail
repo=""
args=("$@")
for ((i=0;i<${#args[@]};i++)); do
  if [[ "${args[$i]}" == "-r" ]] && (( i+1 < ${#args[@]} )); then
    repo="${args[$((i+1))]}"
  fi
done
joined=" $* "
	if [[ "$joined" == *" init"* ]]; then
	  if [[ "${FAKE_RESTIC_FAIL:-}" == "1" ]]; then
	    echo "forced fail" >&2
	    exit 1
	  fi
	  mkdir -p "$repo"
	  touch "$repo/config"
	  echo "created"
	  exit 0
	fi
if [[ "$joined" == *" cat config"* ]]; then
  [[ -f "$repo/config" ]] && exit 0
  echo "missing config" >&2
  exit 1
fi
	if [[ "$joined" == *" backup "* ]]; then
	  if [[ "${FAKE_RESTIC_FAIL_BACKUP:-}" == "1" ]]; then
	    echo "forced fail" >&2
	    exit 1
	  fi
	  if [[ "${FAKE_RESTIC_NO_SUMMARY:-}" == "1" ]]; then
	    echo '{"message_type":"status","percent_done":50}'
	    exit 0
	  fi
  echo '{"message_type":"summary","snapshot_id":"snap-test","files_new":1,"files_changed":0,"files_unmodified":2,"data_added":123,"total_duration":0.2}'
  exit 0
fi
if [[ "$joined" == *" forget "* ]]; then
  if [[ "${FAKE_RESTIC_FAIL_FORGET:-}" == "1" ]]; then
    echo "forced forget fail" >&2
    exit 1
  fi
  echo "pruned"
  exit 0
fi
	if [[ "$joined" == *" snapshots"* ]]; then
	  if [[ "$joined" == *"--json"* ]]; then
	    if [[ "${FAKE_RESTIC_INVALID_SNAPSHOTS_JSON:-}" == "1" ]]; then
	      echo '{'
	      exit 0
	    fi
	    if [[ "${FAKE_RESTIC_SNAPSHOTS_MISSING:-}" == "1" ]]; then
	      echo 'no such file or directory' >&2
	      exit 1
	    fi
	    if [[ "${FAKE_RESTIC_HAS_SNAPSHOTS:-}" == "1" ]]; then
	      echo '[{"id":"snap-test"}]'
	    else
      echo '[]'
    fi
    exit 0
  fi
  echo "ID        Time"
  exit 0
fi
if [[ "$joined" == *" copy "* ]]; then
  echo "copied"
  exit 0
fi
echo "unsupported args: $*" >&2
exit 1
`
}

func fakeCrontabScript() string {
	return `#!/usr/bin/env bash
set -euo pipefail
store="${FAKE_CRONTAB_FILE:?}"
last="${@: -1}"
if [[ "$last" == "-l" ]]; then
  [[ -f "$store" ]] && cat "$store"
  exit 0
fi
if [[ "$last" == "-" ]]; then
  if [[ "${FAKE_CRONTAB_FAIL_INSTALL:-}" == "1" ]]; then
    echo "forced install fail" >&2
    exit 1
  fi
  cat > "$store"
  exit 0
fi
echo "unsupported crontab args: $*" >&2
exit 1
`
}

func fakeSystemctlScript() string {
	return `#!/usr/bin/env bash
set -euo pipefail
store="${FAKE_SYSTEMCTL_LOG:?}"
printf '%s\n' "$*" >> "$store"
exit 0
`
}

func TestDiscoverPaths_RespectsIncludesAndExcludes(t *testing.T) {
	tmp := t.TempDir()
	dir := filepath.Join(tmp, ".claude", "projects")
	require.NoError(t, os.MkdirAll(dir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "keep.jsonl"), []byte("{}"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "skip.jsonl"), []byte("{}"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "other.md"), []byte("#"), 0644))

	registry := []ToolSource{
		{
			Name: "claude",
			Paths: []SourcePath{
				{
					Path:     "~/.claude/projects",
					Includes: []string{"*.jsonl"},
					Excludes: []string{"skip.jsonl"},
				},
			},
		},
	}

	paths, tools, skipped := discoverPaths(newSilentLogger(), registry, tmp)
	assert.Equal(t, []string{filepath.Join(dir, "keep.jsonl")}, paths)
	assert.Equal(t, []string{"claude"}, tools)
	assert.Empty(t, skipped)
}

func TestRunBackup_DryRunDoesNotRequireRestic(t *testing.T) {
	tmp := t.TempDir()
	dataDir := filepath.Join(tmp, ".claude", "projects")
	require.NoError(t, os.MkdirAll(dataDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, "session.jsonl"), []byte("{}\n"), 0644))

	rc := newRuntimeContext()
	result, err := RunBackup(rc, BackupConfig{
		HomeDir:       tmp,
		ExtraScanDirs: []string{},
		DryRun:        true,
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotEmpty(t, result.PathsBackedUp)
}

func TestRunBackup_WritesManifest(t *testing.T) {
	prependFakeBin(t, map[string]string{"restic": fakeResticScript()})

	tmp := t.TempDir()
	dataDir := filepath.Join(tmp, ".claude", "projects")
	repoPath := filepath.Join(tmp, ResticRepoSubdir)
	passwordFile := filepath.Join(tmp, ResticPasswordSubdir)
	manifestFile := filepath.Join(tmp, ResticManifestSubdir)

	require.NoError(t, os.MkdirAll(dataDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, "session.jsonl"), []byte("{}\n"), 0644))
	require.NoError(t, os.MkdirAll(repoPath, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(repoPath, "config"), []byte("ok"), 0600))
	require.NoError(t, os.MkdirAll(filepath.Dir(passwordFile), 0700))
	require.NoError(t, os.WriteFile(passwordFile, []byte("password"), 0400))

	result, err := RunBackup(newRuntimeContext(), BackupConfig{
		User:          "henry",
		HomeDir:       tmp,
		ExtraScanDirs: []string{},
	})
	require.NoError(t, err)
	require.Equal(t, "snap-test", result.SnapshotID)

	data, err := os.ReadFile(manifestFile)
	require.NoError(t, err)

	var manifest BackupManifest
	require.NoError(t, json.Unmarshal(data, &manifest))
	assert.Equal(t, "snap-test", manifest.SnapshotID)
	assert.Contains(t, manifest.ToolsFound, "claude-code")
	assert.Contains(t, manifest.UsersScanned, "henry")
	assert.NotEmpty(t, manifest.PathsIncluded)
}

func TestRunBackup_SuccessUpdatesStatus(t *testing.T) {
	prependFakeBin(t, map[string]string{"restic": fakeResticScript()})

	tmp := t.TempDir()
	dataDir := filepath.Join(tmp, ".claude", "projects")
	repoPath := filepath.Join(tmp, ResticRepoSubdir)
	passwordFile := filepath.Join(tmp, ResticPasswordSubdir)
	statusFile := filepath.Join(tmp, ResticStatusSubdir)

	require.NoError(t, os.MkdirAll(dataDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, "session.jsonl"), []byte("{}\n"), 0644))
	require.NoError(t, os.MkdirAll(repoPath, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(repoPath, "config"), []byte("ok"), 0600))
	require.NoError(t, os.MkdirAll(filepath.Dir(passwordFile), 0700))
	require.NoError(t, os.WriteFile(passwordFile, []byte("password"), 0400))

	rc := newRuntimeContext()
	result, err := RunBackup(rc, BackupConfig{
		HomeDir:       tmp,
		ExtraScanDirs: []string{},
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "snap-test", result.SnapshotID)
	assert.Equal(t, int64(123), result.BytesAdded)

	data, err := os.ReadFile(statusFile)
	require.NoError(t, err)
	var status BackupStatus
	require.NoError(t, json.Unmarshal(data, &status))
	assert.Equal(t, "success", status.LastRunState)
	assert.Equal(t, 1, status.SuccessCount)
	assert.Equal(t, "snap-test", status.LastSnapshotID)
}

func TestRunBackup_LockConflictFails(t *testing.T) {
	prependFakeBin(t, map[string]string{"restic": fakeResticScript()})

	tmp := t.TempDir()
	dataDir := filepath.Join(tmp, ".claude", "projects")
	repoPath := filepath.Join(tmp, ResticRepoSubdir)
	passwordFile := filepath.Join(tmp, ResticPasswordSubdir)
	lockFile := filepath.Join(tmp, ResticLockSubdir)

	require.NoError(t, os.MkdirAll(dataDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, "session.jsonl"), []byte("{}\n"), 0644))
	require.NoError(t, os.MkdirAll(repoPath, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(repoPath, "config"), []byte("ok"), 0600))
	require.NoError(t, os.MkdirAll(filepath.Dir(passwordFile), 0700))
	require.NoError(t, os.WriteFile(passwordFile, []byte("password"), 0400))

	lock, err := acquireBackupLock(lockFile, "")
	require.NoError(t, err)
	defer releaseBackupLock(lock)

	rc := newRuntimeContext()
	_, err = RunBackup(rc, BackupConfig{
		HomeDir:       tmp,
		ExtraScanDirs: []string{},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "acquire backup lock")
	assert.ErrorIs(t, err, ErrBackupAlreadyRunning)
}

func TestRunResticBackup_NoSummaryFails(t *testing.T) {
	prependFakeBin(t, map[string]string{"restic": fakeResticScript()})
	t.Setenv("FAKE_RESTIC_NO_SUMMARY", "1")

	tmp := t.TempDir()
	repoPath := filepath.Join(tmp, ResticRepoSubdir)
	passwordFile := filepath.Join(tmp, ResticPasswordSubdir)
	require.NoError(t, os.MkdirAll(repoPath, 0700))
	require.NoError(t, os.MkdirAll(filepath.Dir(passwordFile), 0700))
	require.NoError(t, os.WriteFile(passwordFile, []byte("password"), 0400))

	_, err := runResticBackup(context.Background(), newSilentLogger(), repoPath, passwordFile, []string{tmp})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no summary")
}

func TestSetup_CreatesRepoPasswordAndCron(t *testing.T) {
	prependFakeBin(t, map[string]string{
		"restic":  fakeResticScript(),
		"crontab": fakeCrontabScript(),
	})

	tmp := t.TempDir()
	crontabStore := filepath.Join(tmp, "crontab.txt")
	t.Setenv("FAKE_CRONTAB_FILE", crontabStore)

	rc := newRuntimeContext()
	result, err := Setup(rc, ScheduleConfig{
		BackupConfig: BackupConfig{
			HomeDir: tmp,
		},
		BackupCron: "0 * * * *",
		PruneCron:  "5 3 * * *",
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.CronConfigured)

	_, statErr := os.Stat(filepath.Join(tmp, ResticRepoSubdir, "config"))
	assert.NoError(t, statErr)
	_, statErr = os.Stat(filepath.Join(tmp, ResticPasswordSubdir))
	assert.NoError(t, statErr)

	cron, err := os.ReadFile(crontabStore)
	require.NoError(t, err)
	assert.Contains(t, string(cron), CronMarker)
	assert.NotContains(t, string(cron), "--user ''")
}

func TestSetup_AllUsers_CreatesSystemdUnits(t *testing.T) {
	prependFakeBin(t, map[string]string{
		"restic":    fakeResticScript(),
		"systemctl": fakeSystemctlScript(),
		"crontab":   fakeCrontabScript(),
	})

	tmp := t.TempDir()
	passwd := filepath.Join(tmp, "passwd")
	homeDir := filepath.Join(tmp, "home", "henry")
	require.NoError(t, os.MkdirAll(homeDir, 0755))
	require.NoError(t, os.WriteFile(passwd, []byte("henry:x:1000:1000::"+homeDir+":/bin/bash\n"), 0644))

	oldGeteuid := osGeteuid
	oldPasswdFile := passwdFilePath
	oldRepo := MachineRepoPath
	oldPassword := MachinePasswordFile
	oldStatus := MachineStatusFile
	oldManifest := MachineManifestFile
	oldLock := MachineLockFile
	oldUnits := SystemdUnitDir
	oldLegacy := findLegacyRepositoriesFn

	osGeteuid = func() int { return 0 }
	passwdFilePath = passwd
	MachineRepoPath = filepath.Join(tmp, "var", "backups", "eos", "restic", "chat-archive")
	MachinePasswordFile = filepath.Join(tmp, "etc", "eos", "restic", "chat-archive-password")
	MachineStatusFile = filepath.Join(tmp, "var", "lib", "eos", "chat-archive-status.json")
	MachineManifestFile = filepath.Join(tmp, "var", "lib", "eos", "chat-archive-manifest.json")
	MachineLockFile = filepath.Join(tmp, "run", "lock", "eos-chat-archive.lock")
	SystemdUnitDir = filepath.Join(tmp, "systemd")
	findLegacyRepositoriesFn = func() []storagePaths { return nil }

	t.Cleanup(func() {
		osGeteuid = oldGeteuid
		passwdFilePath = oldPasswdFile
		MachineRepoPath = oldRepo
		MachinePasswordFile = oldPassword
		MachineStatusFile = oldStatus
		MachineManifestFile = oldManifest
		MachineLockFile = oldLock
		SystemdUnitDir = oldUnits
		findLegacyRepositoriesFn = oldLegacy
	})

	systemctlLog := filepath.Join(tmp, "systemctl.log")
	t.Setenv("FAKE_SYSTEMCTL_LOG", systemctlLog)
	cronStore := filepath.Join(tmp, "cron.txt")
	require.NoError(t, os.WriteFile(cronStore, []byte("# eos-chat-archive: old\n0 * * * * /old\n"), 0600))
	t.Setenv("FAKE_CRONTAB_FILE", cronStore)

	result, err := Setup(newRuntimeContext(), ScheduleConfig{
		BackupConfig: BackupConfig{AllUsers: true},
		BackupCron:   DefaultBackupCron,
		PruneCron:    DefaultPruneCron,
	})
	require.NoError(t, err)
	assert.True(t, result.CronConfigured)

	for _, unit := range []string{BackupServiceName, BackupTimerName, PruneServiceName, PruneTimerName} {
		_, err := os.Stat(filepath.Join(SystemdUnitDir, unit))
		require.NoError(t, err)
	}

	systemctlCalls, err := os.ReadFile(systemctlLog)
	require.NoError(t, err)
	assert.Contains(t, string(systemctlCalls), "daemon-reload")
	assert.Contains(t, string(systemctlCalls), "enable "+BackupTimerName)
	assert.Contains(t, string(systemctlCalls), "start "+PruneTimerName)

	cronData, err := os.ReadFile(cronStore)
	require.NoError(t, err)
	assert.NotContains(t, string(cronData), CronMarker)
}

func TestSetup_DelegatedUserOwnershipFix(t *testing.T) {
	prependFakeBin(t, map[string]string{
		"restic":  fakeResticScript(),
		"crontab": fakeCrontabScript(),
	})

	tmp := t.TempDir()
	t.Setenv("FAKE_CRONTAB_FILE", filepath.Join(tmp, "cron.txt"))

	oldGeteuid := osGeteuid
	oldLookup := userLookup
	oldChown := osChown
	osGeteuid = func() int { return 0 }
	userLookup = func(string) (*user.User, error) {
		return &user.User{Uid: "1001", Gid: "1002"}, nil
	}
	var changed []string
	osChown = func(path string, uid, gid int) error {
		changed = append(changed, path)
		return nil
	}
	t.Cleanup(func() {
		osGeteuid = oldGeteuid
		userLookup = oldLookup
		osChown = oldChown
	})

	_, err := Setup(newRuntimeContext(), ScheduleConfig{
		BackupConfig: BackupConfig{
			User:    "henry",
			HomeDir: tmp,
		},
		BackupCron: DefaultBackupCron,
		PruneCron:  DefaultPruneCron,
	})
	require.NoError(t, err)
	assert.Contains(t, changed, filepath.Join(tmp, ".eos"))
}

func TestConfigureSystemdTimers_SystemctlFailure(t *testing.T) {
	prependFakeBin(t, map[string]string{
		"systemctl": `#!/usr/bin/env bash
set -euo pipefail
echo "forced systemctl failure" >&2
exit 1
`,
	})

	oldUnits := SystemdUnitDir
	SystemdUnitDir = filepath.Join(t.TempDir(), "systemd")
	t.Cleanup(func() {
		SystemdUnitDir = oldUnits
	})

	err := configureSystemdTimers(newRuntimeContext(), ScheduleConfig{
		BackupCron: DefaultBackupCron,
		PruneCron:  DefaultPruneCron,
	})
	require.Error(t, err)
}

func TestRunPrune_Success(t *testing.T) {
	prependFakeBin(t, map[string]string{"restic": fakeResticScript()})

	tmp := t.TempDir()
	repoPath := filepath.Join(tmp, ResticRepoSubdir)
	passwordFile := filepath.Join(tmp, ResticPasswordSubdir)

	require.NoError(t, os.MkdirAll(repoPath, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(repoPath, "config"), []byte("ok"), 0600))
	require.NoError(t, os.MkdirAll(filepath.Dir(passwordFile), 0700))
	require.NoError(t, os.WriteFile(passwordFile, []byte("password"), 0400))

	rc := newRuntimeContext()
	err := RunPrune(rc, BackupConfig{
		HomeDir: tmp,
	})
	require.NoError(t, err)
}

func TestRunBackup_NoPaths(t *testing.T) {
	tmp := t.TempDir()
	rc := newRuntimeContext()
	statusFile := filepath.Join(tmp, ResticStatusSubdir)
	emptyScanDir := filepath.Join(tmp, "scan")
	require.NoError(t, os.MkdirAll(emptyScanDir, 0755))

	result, err := RunBackup(rc, BackupConfig{
		HomeDir:       tmp,
		ExtraScanDirs: []string{emptyScanDir},
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Empty(t, result.PathsBackedUp)

	data, readErr := os.ReadFile(statusFile)
	require.NoError(t, readErr)
	var status BackupStatus
	require.NoError(t, json.Unmarshal(data, &status))
	assert.Equal(t, "noop", status.LastRunState)
	assert.Equal(t, 0, status.SuccessCount)
	assert.Equal(t, 0, status.FailureCount)
}

func TestRunBackup_RepoNotInitialized(t *testing.T) {
	prependFakeBin(t, map[string]string{"restic": fakeResticScript()})

	tmp := t.TempDir()
	dataDir := filepath.Join(tmp, ".claude", "projects")
	passwordFile := filepath.Join(tmp, ResticPasswordSubdir)
	require.NoError(t, os.MkdirAll(dataDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, "session.jsonl"), []byte("{}\n"), 0644))
	require.NoError(t, os.MkdirAll(filepath.Dir(passwordFile), 0700))
	require.NoError(t, os.WriteFile(passwordFile, []byte("password"), 0400))

	rc := newRuntimeContext()
	_, err := RunBackup(rc, BackupConfig{
		HomeDir:       tmp,
		ExtraScanDirs: []string{},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "repository initialization")
	assert.ErrorIs(t, err, ErrRepositoryNotInitialized)
}

func TestRunBackup_ResticFailureUpdatesFailureStatus(t *testing.T) {
	prependFakeBin(t, map[string]string{"restic": fakeResticScript()})
	t.Setenv("FAKE_RESTIC_FAIL_BACKUP", "1")

	tmp := t.TempDir()
	dataDir := filepath.Join(tmp, ".claude", "projects")
	repoPath := filepath.Join(tmp, ResticRepoSubdir)
	passwordFile := filepath.Join(tmp, ResticPasswordSubdir)
	statusFile := filepath.Join(tmp, ResticStatusSubdir)
	require.NoError(t, os.MkdirAll(dataDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, "session.jsonl"), []byte("{}\n"), 0644))
	require.NoError(t, os.MkdirAll(repoPath, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(repoPath, "config"), []byte("ok"), 0600))
	require.NoError(t, os.MkdirAll(filepath.Dir(passwordFile), 0700))
	require.NoError(t, os.WriteFile(passwordFile, []byte("password"), 0400))

	rc := newRuntimeContext()
	_, err := RunBackup(rc, BackupConfig{
		HomeDir:       tmp,
		ExtraScanDirs: []string{},
	})
	require.Error(t, err)

	data, readErr := os.ReadFile(statusFile)
	require.NoError(t, readErr)
	var status BackupStatus
	require.NoError(t, json.Unmarshal(data, &status))
	assert.Equal(t, "failure", status.LastRunState)
	assert.Contains(t, status.LastError, "restic backup failed")
	assert.Equal(t, 1, status.FailureCount)
}

func TestSetup_DryRun(t *testing.T) {
	tmp := t.TempDir()
	rc := newRuntimeContext()

	result, err := Setup(rc, ScheduleConfig{
		BackupConfig: BackupConfig{
			HomeDir: tmp,
			DryRun:  true,
		},
		BackupCron: "0 * * * *",
		PruneCron:  "5 3 * * *",
	})
	require.NoError(t, err)
	assert.False(t, result.CronConfigured)
}

func TestSetup_MissingResticFails(t *testing.T) {
	tmp := t.TempDir()
	emptyPath := t.TempDir()
	t.Setenv("PATH", emptyPath)

	rc := newRuntimeContext()
	_, err := Setup(rc, ScheduleConfig{
		BackupConfig: BackupConfig{
			HomeDir: tmp,
		},
		BackupCron: "0 * * * *",
		PruneCron:  "5 3 * * *",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrResticNotInstalled)
}

func TestSetup_CronFailureBecomesWarning(t *testing.T) {
	prependFakeBin(t, map[string]string{
		"restic": fakeResticScript(),
		"crontab": `#!/usr/bin/env bash
set -euo pipefail
echo "forced crontab failure" >&2
exit 1
`,
	})

	tmp := t.TempDir()
	rc := newRuntimeContext()
	result, err := Setup(rc, ScheduleConfig{
		BackupConfig: BackupConfig{
			HomeDir: tmp,
		},
		BackupCron: "0 * * * *",
		PruneCron:  "5 3 * * *",
	})
	require.NoError(t, err)
	assert.False(t, result.CronConfigured)
	assert.NotEmpty(t, result.Warnings)
}

func TestRunPrune_DryRun(t *testing.T) {
	tmp := t.TempDir()
	rc := newRuntimeContext()

	err := RunPrune(rc, BackupConfig{
		HomeDir: tmp,
		DryRun:  true,
	})
	require.NoError(t, err)
}

func TestEnsureRestic_Missing(t *testing.T) {
	emptyPath := t.TempDir()
	t.Setenv("PATH", emptyPath)
	err := ensureRestic(newRuntimeContext())
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrResticNotInstalled)
}

func TestEnsureRestic_Installed(t *testing.T) {
	prependFakeBin(t, map[string]string{"restic": fakeResticScript()})
	require.NoError(t, ensureRestic(newRuntimeContext()))
}

func TestOpErrorUnwrap(t *testing.T) {
	base := assert.AnError
	err := &opError{Op: "op", Err: base}
	assert.Equal(t, "op: assert.AnError general error for testing", err.Error())
	assert.ErrorIs(t, err, base)
	assert.Equal(t, base, err.Unwrap())
}

func TestShellQuote(t *testing.T) {
	assert.Equal(t, "''", shellQuote(""))
	assert.Equal(t, "'abc'", shellQuote("abc"))
	assert.True(t, strings.Contains(shellQuote("a'b"), "'\\''"))
}

func TestEnsureOwnershipRecursive_InvalidUser(t *testing.T) {
	oldGeteuid := osGeteuid
	osGeteuid = func() int { return 0 }
	t.Cleanup(func() {
		osGeteuid = oldGeteuid
	})

	err := ensureOwnershipRecursive(t.TempDir(), "__definitely_missing_user__")
	require.Error(t, err)
}

func TestEnsureOwnershipRecursive_Success(t *testing.T) {
	tmp := t.TempDir()
	nestedFile := filepath.Join(tmp, "nested", "file.txt")
	require.NoError(t, os.MkdirAll(filepath.Dir(nestedFile), 0755))
	require.NoError(t, os.WriteFile(nestedFile, []byte("ok"), 0644))

	oldLookup := userLookup
	oldChown := osChown
	oldGeteuid := osGeteuid
	userLookup = func(string) (*user.User, error) {
		return &user.User{Uid: "123", Gid: "456"}, nil
	}
	osGeteuid = func() int { return 0 }
	var seen []string
	osChown = func(path string, uid, gid int) error {
		seen = append(seen, path)
		assert.Equal(t, 123, uid)
		assert.Equal(t, 456, gid)
		return nil
	}
	t.Cleanup(func() {
		userLookup = oldLookup
		osChown = oldChown
		osGeteuid = oldGeteuid
	})

	require.NoError(t, ensureOwnershipRecursive(tmp, "henry"))
	assert.Contains(t, seen, tmp)
	assert.Contains(t, seen, filepath.Join(tmp, "nested"))
	assert.Contains(t, seen, nestedFile)
}

func TestEnsureOwnershipRecursive_InvalidIDs(t *testing.T) {
	oldLookup := userLookup
	oldGeteuid := osGeteuid
	userLookup = func(string) (*user.User, error) {
		return &user.User{Uid: "bad", Gid: "456"}, nil
	}
	osGeteuid = func() int { return 0 }
	t.Cleanup(func() {
		userLookup = oldLookup
		osGeteuid = oldGeteuid
	})

	err := ensureOwnershipRecursive(t.TempDir(), "henry")
	require.Error(t, err)
}

func TestGeneratePassword_ParentMkdirFailure(t *testing.T) {
	tmp := t.TempDir()
	parentFile := filepath.Join(tmp, "not-a-dir")
	require.NoError(t, os.WriteFile(parentFile, []byte("x"), 0600))

	err := generatePassword(filepath.Join(parentFile, "password"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create directory")
}

func TestUpdateStatus_DirectoryCreationFailure(t *testing.T) {
	tmp := t.TempDir()
	parentFile := filepath.Join(tmp, "not-a-dir")
	require.NoError(t, os.WriteFile(parentFile, []byte("x"), 0600))

	updateStatus(newSilentLogger(), filepath.Join(parentFile, "status.json"), backupStatusUpdate{
		Result: &BackupResult{
			SnapshotID: "abc",
		},
		ToolsFound: []string{"claude-code"},
	}, "")
}

func TestSetup_SecondRunReusesPassword(t *testing.T) {
	prependFakeBin(t, map[string]string{
		"restic":  fakeResticScript(),
		"crontab": fakeCrontabScript(),
	})
	tmp := t.TempDir()
	t.Setenv("FAKE_CRONTAB_FILE", filepath.Join(tmp, "cron.txt"))

	rc := newRuntimeContext()
	first, err := Setup(rc, ScheduleConfig{
		BackupConfig: BackupConfig{HomeDir: tmp},
		BackupCron:   DefaultBackupCron,
		PruneCron:    DefaultPruneCron,
	})
	require.NoError(t, err)
	assert.True(t, first.PasswordGenerated)

	second, err := Setup(rc, ScheduleConfig{
		BackupConfig: BackupConfig{HomeDir: tmp},
		BackupCron:   DefaultBackupCron,
		PruneCron:    DefaultPruneCron,
	})
	require.NoError(t, err)
	assert.False(t, second.PasswordGenerated)
}

func TestInitRepo_AlreadyInitialized(t *testing.T) {
	prependFakeBin(t, map[string]string{"restic": fakeResticScript()})
	tmp := t.TempDir()
	repoPath := filepath.Join(tmp, ResticRepoSubdir)
	passwordFile := filepath.Join(tmp, ResticPasswordSubdir)
	require.NoError(t, os.MkdirAll(repoPath, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(repoPath, "config"), []byte("ok"), 0600))
	require.NoError(t, os.MkdirAll(filepath.Dir(passwordFile), 0700))
	require.NoError(t, os.WriteFile(passwordFile, []byte("password"), 0400))

	require.NoError(t, initRepo(newRuntimeContext(), repoPath, passwordFile))
}

func TestConfigureCron_RemovesExistingMarker(t *testing.T) {
	prependFakeBin(t, map[string]string{"crontab": fakeCrontabScript()})
	tmp := t.TempDir()
	cronFile := filepath.Join(tmp, "cron.txt")
	existing := "# eos-chat-archive: old\n0 * * * * /old\n# keep-me\n"
	require.NoError(t, os.WriteFile(cronFile, []byte(existing), 0600))
	t.Setenv("FAKE_CRONTAB_FILE", cronFile)

	err := configureCron(newRuntimeContext(), ScheduleConfig{
		BackupConfig: BackupConfig{User: "test user"},
		BackupCron:   "0 * * * *",
		PruneCron:    "5 3 * * *",
	})
	require.NoError(t, err)

	data, readErr := os.ReadFile(cronFile)
	require.NoError(t, readErr)
	content := string(data)
	assert.Contains(t, content, "# keep-me")
	assert.GreaterOrEqual(t, strings.Count(content, CronMarker), 2)
	assert.Contains(t, content, "--user 'test user'")
}

func TestRunPrune_NotInitializedFails(t *testing.T) {
	prependFakeBin(t, map[string]string{"restic": fakeResticScript()})
	err := RunPrune(newRuntimeContext(), BackupConfig{HomeDir: t.TempDir()})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not initialized")
}

func TestRunBackup_ResticMissing(t *testing.T) {
	tmp := t.TempDir()
	dataDir := filepath.Join(tmp, ".claude", "projects")
	repoPath := filepath.Join(tmp, ResticRepoSubdir)
	passwordFile := filepath.Join(tmp, ResticPasswordSubdir)
	require.NoError(t, os.MkdirAll(dataDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(dataDir, "session.jsonl"), []byte("{}\n"), 0644))
	require.NoError(t, os.MkdirAll(repoPath, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(repoPath, "config"), []byte("ok"), 0600))
	require.NoError(t, os.MkdirAll(filepath.Dir(passwordFile), 0700))
	require.NoError(t, os.WriteFile(passwordFile, []byte("password"), 0400))
	t.Setenv("PATH", t.TempDir())

	_, err := RunBackup(newRuntimeContext(), BackupConfig{
		HomeDir:       tmp,
		ExtraScanDirs: []string{},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "restic")
	assert.ErrorIs(t, err, ErrResticNotInstalled)
}

func TestRunBackup_ResolveHomeError(t *testing.T) {
	_, err := RunBackup(newRuntimeContext(), BackupConfig{User: "__missing_user__"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "resolve backup users")
}

func TestResolveHomeDir_ExistingUserLookup(t *testing.T) {
	current, err := user.Current()
	require.NoError(t, err)
	home, err := resolveHomeDir(current.Username)
	require.NoError(t, err)
	assert.NotEmpty(t, home)
}

func TestAcquireBackupLock_DirectoryError(t *testing.T) {
	tmp := t.TempDir()
	parentFile := filepath.Join(tmp, "not-a-dir")
	require.NoError(t, os.WriteFile(parentFile, []byte("x"), 0600))
	_, err := acquireBackupLock(filepath.Join(parentFile, "lock"), "")
	require.Error(t, err)
}

func TestEnsureOwnership_Success(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "status.json")
	require.NoError(t, os.WriteFile(tmpFile, []byte("{}"), 0600))

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
		assert.Equal(t, tmpFile, path)
		assert.Equal(t, 1001, uid)
		assert.Equal(t, 1002, gid)
		return nil
	}
	t.Cleanup(func() {
		osGeteuid = oldGeteuid
		userLookup = oldLookup
		osChown = oldChown
	})

	require.NoError(t, ensureOwnership(tmpFile, "henry"))
	assert.True(t, called)
}

func TestEnsureOwnership_NotExistIsIgnored(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "status.json")

	oldGeteuid := osGeteuid
	oldLookup := userLookup
	oldChown := osChown
	osGeteuid = func() int { return 0 }
	userLookup = func(string) (*user.User, error) {
		return &user.User{Uid: "1001", Gid: "1002"}, nil
	}
	osChown = func(path string, uid, gid int) error {
		return os.ErrNotExist
	}
	t.Cleanup(func() {
		osGeteuid = oldGeteuid
		userLookup = oldLookup
		osChown = oldChown
	})

	require.NoError(t, ensureOwnership(tmpFile, "henry"))
}

func TestEnsureOwnership_LookupError(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "status.json")
	require.NoError(t, os.WriteFile(tmpFile, []byte("{}"), 0600))

	oldGeteuid := osGeteuid
	oldLookup := userLookup
	osGeteuid = func() int { return 0 }
	userLookup = func(string) (*user.User, error) {
		return nil, assert.AnError
	}
	t.Cleanup(func() {
		osGeteuid = oldGeteuid
		userLookup = oldLookup
	})

	err := ensureOwnership(tmpFile, "henry")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "lookup user")
}

func TestEnsureOwnership_ChownError(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "status.json")
	require.NoError(t, os.WriteFile(tmpFile, []byte("{}"), 0600))

	oldGeteuid := osGeteuid
	oldLookup := userLookup
	oldChown := osChown
	osGeteuid = func() int { return 0 }
	userLookup = func(string) (*user.User, error) {
		return &user.User{Uid: "1001", Gid: "1002"}, nil
	}
	osChown = func(path string, uid, gid int) error {
		return assert.AnError
	}
	t.Cleanup(func() {
		osGeteuid = oldGeteuid
		userLookup = oldLookup
		osChown = oldChown
	})

	err := ensureOwnership(tmpFile, "henry")
	require.ErrorIs(t, err, assert.AnError)
}

func TestReleaseBackupLock_Nil(t *testing.T) {
	releaseBackupLock(nil)
}

func TestCollectMatchingFiles_ExcludedDirectory(t *testing.T) {
	tmp := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(tmp, "ignore"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "ignore", "a.json"), []byte("{}"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "keep.json"), []byte("{}"), 0644))
	matches := collectMatchingFiles(tmp, []string{"*.json"}, []string{"ignore"})
	assert.Equal(t, []string{filepath.Join(tmp, "keep.json")}, matches)
}

func TestGeneratePassword_WriteFailure(t *testing.T) {
	tmp := t.TempDir()
	targetDir := filepath.Join(tmp, "as-dir")
	require.NoError(t, os.MkdirAll(targetDir, 0700))
	err := generatePassword(targetDir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to write password file")
}

func TestUpdateStatus_RenameFailure(t *testing.T) {
	tmp := t.TempDir()
	statusDir := filepath.Join(tmp, "status-target")
	require.NoError(t, os.MkdirAll(statusDir, 0700))
	updateStatus(newSilentLogger(), statusDir, backupStatusUpdate{
		Result: &BackupResult{SnapshotID: "x"},
	}, "")
}

func TestSetup_ResolveHomeFailure(t *testing.T) {
	_, err := Setup(newRuntimeContext(), ScheduleConfig{
		BackupConfig: BackupConfig{User: "__missing_user__"},
		BackupCron:   DefaultBackupCron,
		PruneCron:    DefaultPruneCron,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "resolve backup users")
}

func TestSetup_InitRepoFailure(t *testing.T) {
	prependFakeBin(t, map[string]string{
		"restic":  fakeResticScript(),
		"crontab": fakeCrontabScript(),
	})
	t.Setenv("FAKE_RESTIC_FAIL", "1")
	tmp := t.TempDir()
	t.Setenv("FAKE_CRONTAB_FILE", filepath.Join(tmp, "cron.txt"))

	_, err := Setup(newRuntimeContext(), ScheduleConfig{
		BackupConfig: BackupConfig{HomeDir: tmp},
		BackupCron:   DefaultBackupCron,
		PruneCron:    DefaultPruneCron,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "initialize restic repository")
}

func TestConfigureCron_NoCrontabBinary(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	err := configureCron(newRuntimeContext(), ScheduleConfig{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "crontab not found")
}

func TestRunPrune_ResticFailure(t *testing.T) {
	prependFakeBin(t, map[string]string{"restic": fakeResticScript()})
	t.Setenv("FAKE_RESTIC_FAIL_FORGET", "1")

	tmp := t.TempDir()
	repoPath := filepath.Join(tmp, ResticRepoSubdir)
	passwordFile := filepath.Join(tmp, ResticPasswordSubdir)
	require.NoError(t, os.MkdirAll(repoPath, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(repoPath, "config"), []byte("ok"), 0600))
	require.NoError(t, os.MkdirAll(filepath.Dir(passwordFile), 0700))
	require.NoError(t, os.WriteFile(passwordFile, []byte("password"), 0400))

	err := RunPrune(newRuntimeContext(), BackupConfig{HomeDir: tmp})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "prune failed")
}

func TestRunPrune_ResolveHomeError(t *testing.T) {
	err := RunPrune(newRuntimeContext(), BackupConfig{User: "__missing_user__"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "resolve backup users")
}

func TestListSnapshots_Success(t *testing.T) {
	prependFakeBin(t, map[string]string{"restic": fakeResticScript()})

	tmp := t.TempDir()
	repoPath := filepath.Join(tmp, ResticRepoSubdir)
	passwordFile := filepath.Join(tmp, ResticPasswordSubdir)
	require.NoError(t, os.MkdirAll(repoPath, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(repoPath, "config"), []byte("ok"), 0600))
	require.NoError(t, os.MkdirAll(filepath.Dir(passwordFile), 0700))
	require.NoError(t, os.WriteFile(passwordFile, []byte("password"), 0400))

	out, err := ListSnapshots(newRuntimeContext(), BackupConfig{HomeDir: tmp})
	require.NoError(t, err)
	assert.Contains(t, out, "ID")
}

func TestListSnapshots_ResticMissing(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("PATH", t.TempDir())

	_, err := ListSnapshots(newRuntimeContext(), BackupConfig{HomeDir: tmp})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrResticNotInstalled)
}

func TestListSnapshots_RepoNotInitialized(t *testing.T) {
	prependFakeBin(t, map[string]string{"restic": fakeResticScript()})

	tmp := t.TempDir()
	passwordFile := filepath.Join(tmp, ResticPasswordSubdir)
	require.NoError(t, os.MkdirAll(filepath.Dir(passwordFile), 0700))
	require.NoError(t, os.WriteFile(passwordFile, []byte("password"), 0400))

	_, err := ListSnapshots(newRuntimeContext(), BackupConfig{HomeDir: tmp})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrRepositoryNotInitialized)
}

func TestFindLegacyRepositories_UsesUserStoragePaths(t *testing.T) {
	tmp := t.TempDir()
	homeDir := filepath.Join(tmp, "home", "henry")
	repoPath := filepath.Join(homeDir, ResticRepoSubdir)
	passwordPath := filepath.Join(homeDir, ResticPasswordSubdir)
	passwd := filepath.Join(tmp, "passwd")

	require.NoError(t, os.MkdirAll(filepath.Dir(repoPath), 0755))
	require.NoError(t, os.MkdirAll(repoPath, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(repoPath, "config"), []byte("ok"), 0600))
	require.NoError(t, os.MkdirAll(filepath.Dir(passwordPath), 0700))
	require.NoError(t, os.WriteFile(passwordPath, []byte("password"), 0400))
	require.NoError(t, os.WriteFile(passwd, []byte("henry:x:1000:1000::"+homeDir+":/bin/bash\n"), 0644))

	oldGeteuid := osGeteuid
	oldPasswdFile := passwdFilePath
	osGeteuid = func() int { return 0 }
	passwdFilePath = passwd
	t.Cleanup(func() {
		osGeteuid = oldGeteuid
		passwdFilePath = oldPasswdFile
	})

	sources := findLegacyRepositories()
	require.Len(t, sources, 1)
	assert.Equal(t, filepath.Join(homeDir, ResticManifestSubdir), sources[0].ManifestFile)
	assert.Equal(t, repoPath, sources[0].Repo)
	assert.Equal(t, passwordPath, sources[0].PasswordFile)
}

func TestFindLegacyRepositories_ReadFailureReturnsNil(t *testing.T) {
	oldGeteuid := osGeteuid
	oldPasswdFile := passwdFilePath
	osGeteuid = func() int { return 0 }
	passwdFilePath = filepath.Join(t.TempDir(), "missing-passwd")
	t.Cleanup(func() {
		osGeteuid = oldGeteuid
		passwdFilePath = oldPasswdFile
	})

	assert.Nil(t, findLegacyRepositories())
}

func TestBackupCronToOnCalendar(t *testing.T) {
	assert.Equal(t, "hourly", backupCronToOnCalendar(newRuntimeContext(), ""))
	assert.Equal(t, "daily", backupCronToOnCalendar(newRuntimeContext(), "0 0 * * *"))
}

func TestRepoHasTaggedSnapshots(t *testing.T) {
	prependFakeBin(t, map[string]string{"restic": fakeResticScript()})

	ok, err := repoHasTaggedSnapshots(newRuntimeContext(), "/tmp/repo", "/tmp/password")
	require.NoError(t, err)
	assert.False(t, ok)

	t.Setenv("FAKE_RESTIC_HAS_SNAPSHOTS", "1")
	ok, err = repoHasTaggedSnapshots(newRuntimeContext(), "/tmp/repo", "/tmp/password")
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestRepoHasTaggedSnapshots_ToleratesMissingRepoAndBadJSON(t *testing.T) {
	prependFakeBin(t, map[string]string{"restic": fakeResticScript()})

	t.Setenv("FAKE_RESTIC_SNAPSHOTS_MISSING", "1")
	ok, err := repoHasTaggedSnapshots(newRuntimeContext(), "/tmp/repo", "/tmp/password")
	require.NoError(t, err)
	assert.False(t, ok)

	t.Setenv("FAKE_RESTIC_SNAPSHOTS_MISSING", "")
	t.Setenv("FAKE_RESTIC_INVALID_SNAPSHOTS_JSON", "1")
	ok, err = repoHasTaggedSnapshots(newRuntimeContext(), "/tmp/repo", "/tmp/password")
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestCopySnapshots(t *testing.T) {
	prependFakeBin(t, map[string]string{"restic": fakeResticScript()})

	err := copySnapshots(newRuntimeContext(), storagePaths{
		Repo:         "/tmp/source",
		PasswordFile: "/tmp/source-password",
	}, storagePaths{
		Repo:         "/tmp/destination",
		PasswordFile: "/tmp/destination-password",
	})
	require.NoError(t, err)
}

func TestMigrateLegacyRepositories_CopiesLegacyRepos(t *testing.T) {
	prependFakeBin(t, map[string]string{"restic": fakeResticScript()})

	oldLegacy := findLegacyRepositoriesFn
	findLegacyRepositoriesFn = func() []storagePaths {
		return []storagePaths{
			{
				Repo:         "/tmp/source",
				PasswordFile: "/tmp/source-password",
			},
			{
				Repo:         "/tmp/destination",
				PasswordFile: "/tmp/destination-password",
			},
		}
	}
	t.Cleanup(func() {
		findLegacyRepositoriesFn = oldLegacy
	})

	err := migrateLegacyRepositories(newRuntimeContext(), storagePaths{
		Repo:         "/tmp/destination",
		PasswordFile: "/tmp/destination-password",
	})
	require.NoError(t, err)
}

func TestCleanupLegacyCronEntries_SkipsRoot(t *testing.T) {
	prependFakeBin(t, map[string]string{"crontab": fakeCrontabScript()})
	cronStore := filepath.Join(t.TempDir(), "cron.txt")
	t.Setenv("FAKE_CRONTAB_FILE", cronStore)

	err := cleanupLegacyCronEntries(newRuntimeContext(), []scannedUser{
		{Username: RootUsername},
		{Username: "henry"},
	})
	require.NoError(t, err)
}

func TestCleanupLegacyCronEntries_ReportsInstallFailure(t *testing.T) {
	prependFakeBin(t, map[string]string{"crontab": fakeCrontabScript()})
	cronStore := filepath.Join(t.TempDir(), "cron.txt")
	require.NoError(t, os.WriteFile(cronStore, []byte("# eos-chat-archive: old\n0 * * * * /old\n"), 0600))
	t.Setenv("FAKE_CRONTAB_FILE", cronStore)
	t.Setenv("FAKE_CRONTAB_FAIL_INSTALL", "1")

	err := cleanupLegacyCronEntries(newRuntimeContext(), []scannedUser{{Username: "henry"}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "henry")
}

func TestRemoveCronMarkerForUser_NoCrontabBinary(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	require.NoError(t, removeCronMarkerForUser("henry"))
}

func TestMigrateLegacyRepositories_SkipsCopyWhenDestinationAlreadyHasSnapshots(t *testing.T) {
	prependFakeBin(t, map[string]string{"restic": fakeResticScript()})
	t.Setenv("FAKE_RESTIC_HAS_SNAPSHOTS", "1")

	oldLegacy := findLegacyRepositoriesFn
	findLegacyRepositoriesFn = func() []storagePaths {
		return []storagePaths{{Repo: "/tmp/source", PasswordFile: "/tmp/source-password"}}
	}
	t.Cleanup(func() {
		findLegacyRepositoriesFn = oldLegacy
	})

	err := migrateLegacyRepositories(newRuntimeContext(), storagePaths{
		Repo:         "/tmp/destination",
		PasswordFile: "/tmp/destination-password",
	})
	require.NoError(t, err)
}
