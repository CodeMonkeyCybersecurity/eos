package backup

import (
	"context"
	"errors"
	"expvar"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"go.uber.org/zap"
)

func testRuntimeContext() *eos_io.RuntimeContext {
	return &eos_io.RuntimeContext{Ctx: context.Background(), Log: zap.NewNop()}
}

func TestResolveRepositoryNameFromConfig(t *testing.T) {
	cfg := &Config{
		DefaultRepository: "default-repo",
		Repositories: map[string]Repository{
			"default-repo": {Name: "default-repo", Backend: "local", URL: "/tmp/default"},
			"explicit":     {Name: "explicit", Backend: "local", URL: "/tmp/explicit"},
		},
	}

	t.Run("explicit repository", func(t *testing.T) {
		got, err := ResolveRepositoryNameFromConfig(cfg, "explicit")
		if err != nil {
			t.Fatalf("ResolveRepositoryNameFromConfig() error = %v", err)
		}
		if got != "explicit" {
			t.Fatalf("got %q, want explicit", got)
		}
	})

	t.Run("default repository fallback", func(t *testing.T) {
		before := readExpvarInt(t, backupRepositoryResolutionTotal, "default_success")
		got, err := ResolveRepositoryNameFromConfig(cfg, "")
		if err != nil {
			t.Fatalf("ResolveRepositoryNameFromConfig() error = %v", err)
		}
		if got != "default-repo" {
			t.Fatalf("got %q, want default-repo", got)
		}
		after := readExpvarInt(t, backupRepositoryResolutionTotal, "default_success")
		if after <= before {
			t.Fatalf("expected default_success counter to increase, before=%d after=%d", before, after)
		}
	})

	t.Run("missing default", func(t *testing.T) {
		cfgNoDefault := &Config{Repositories: cfg.Repositories}
		_, err := ResolveRepositoryNameFromConfig(cfgNoDefault, "")
		if !errors.Is(err, ErrRepositoryNotSpecified) {
			t.Fatalf("expected ErrRepositoryNotSpecified, got %v", err)
		}
	})

	t.Run("repository not found", func(t *testing.T) {
		_, err := ResolveRepositoryNameFromConfig(cfg, "missing")
		if err == nil {
			t.Fatal("expected error for missing repository")
		}
	})
}

func TestRecordRepositoryResolution_CustomSource(t *testing.T) {
	before := readExpvarInt(t, backupRepositoryResolutionTotal, "quick_default_success")
	RecordRepositoryResolution("quick_default", true)
	after := readExpvarInt(t, backupRepositoryResolutionTotal, "quick_default_success")
	if after <= before {
		t.Fatalf("expected quick_default_success to increase, before=%d after=%d", before, after)
	}
}

func readExpvarInt(t *testing.T, m interface{ Get(string) expvar.Var }, key string) int64 {
	t.Helper()

	v := m.Get(key)
	if v == nil {
		return 0
	}

	var value int64
	if _, err := fmt.Sscanf(v.String(), "%d", &value); err != nil {
		t.Fatalf("failed to parse expvar %s=%q: %v", key, v.String(), err)
	}
	return value
}

func TestLoadAndSaveConfig_PathSelection(t *testing.T) {
	rc := testRuntimeContext()
	tmpDir := t.TempDir()

	canonicalPath := filepath.Join(tmpDir, "backup.yaml")
	legacyPath := filepath.Join(tmpDir, "backup", "config.yaml")

	origRead := configReadCandidates
	origWritePath := configWritePath
	origWriteDir := configWriteDir
	t.Cleanup(func() {
		configReadCandidates = origRead
		configWritePath = origWritePath
		configWriteDir = origWriteDir
	})

	configReadCandidates = []string{canonicalPath, legacyPath}
	configWritePath = canonicalPath
	configWriteDir = tmpDir

	legacyContent := []byte(`
default_repository: local
repositories:
  local:
    name: local
    backend: local
    url: /var/lib/eos/backups
profiles:
  system:
    name: system
    repository: local
    paths:
      - /etc
`)

	if err := os.MkdirAll(filepath.Dir(legacyPath), 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(legacyPath, legacyContent, 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	cfg, err := LoadConfig(rc)
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}
	if cfg.DefaultRepository != "local" {
		t.Fatalf("DefaultRepository = %q, want local", cfg.DefaultRepository)
	}
	if got := readExpvarInt(t, backupConfigSourceTotal, "legacy_success"); got == 0 {
		t.Fatalf("expected legacy_success counter to be > 0, got %d", got)
	}

	if err := SaveConfig(rc, cfg); err != nil {
		t.Fatalf("SaveConfig() error = %v", err)
	}

	if _, err := os.Stat(canonicalPath); err != nil {
		t.Fatalf("canonical config file not written: %v", err)
	}
}

func TestLoadConfigPermissionDeniedFailsFast(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permission-denied test requires non-root execution")
	}

	rc := testRuntimeContext()
	tmpDir := t.TempDir()

	canonicalPath := filepath.Join(tmpDir, "backup.yaml")
	legacyPath := filepath.Join(tmpDir, "backup", "config.yaml")

	origRead := configReadCandidates
	t.Cleanup(func() {
		configReadCandidates = origRead
	})
	configReadCandidates = []string{canonicalPath, legacyPath}

	legacyContent := []byte(`
default_repository: local
repositories:
  local:
    name: local
    backend: local
    url: /var/lib/eos/backups
profiles:
  system:
    name: system
    repository: local
    paths:
      - /etc
`)
	if err := os.MkdirAll(filepath.Dir(legacyPath), 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(legacyPath, legacyContent, 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := os.WriteFile(canonicalPath, legacyContent, 0o600); err != nil {
		t.Fatalf("WriteFile() canonical error = %v", err)
	}
	if err := os.Chmod(canonicalPath, 0); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(canonicalPath, 0o600)
	})

	before := readExpvarInt(t, backupConfigLoadTotal, "permission_denied_failure")
	_, err := LoadConfig(rc)
	if err == nil {
		t.Fatal("expected permission denied error")
	}
	if !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("expected permission denied error, got %v", err)
	}
	after := readExpvarInt(t, backupConfigLoadTotal, "permission_denied_failure")
	if after <= before {
		t.Fatalf("expected permission_denied_failure to increase, before=%d after=%d", before, after)
	}
}

func TestStoreLocalPassword(t *testing.T) {
	tmpDir := t.TempDir()
	origSecretsDir := secretsDirPath
	secretsDirPath = tmpDir
	t.Cleanup(func() {
		secretsDirPath = origSecretsDir
	})

	if err := storeLocalPassword("repo1", "super-secret"); err != nil {
		t.Fatalf("storeLocalPassword() error = %v", err)
	}

	passwordPath := filepath.Join(tmpDir, "repo1.password")
	content, err := os.ReadFile(passwordPath)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(content) != "super-secret" {
		t.Fatalf("password content = %q, want super-secret", string(content))
	}

	info, err := os.Stat(passwordPath)
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if info.Mode().Perm() != PasswordFilePerm {
		t.Fatalf("password file mode = %o, want %o", info.Mode().Perm(), PasswordFilePerm)
	}

	if err := storeLocalPassword("../bad", "x"); err == nil {
		t.Fatal("expected invalid repository name error")
	}
}

func TestEnsureSecretsDirSecure_FixesMode(t *testing.T) {
	tmpDir := t.TempDir()
	secretsPath := filepath.Join(tmpDir, "secrets")
	if err := os.MkdirAll(secretsPath, 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.Chmod(secretsPath, 0o755); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}

	if err := ensureSecretsDirSecure(secretsPath); err != nil {
		t.Fatalf("ensureSecretsDirSecure() error = %v", err)
	}

	info, err := os.Stat(secretsPath)
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if info.Mode().Perm() != PasswordDirPerm {
		t.Fatalf("secrets directory mode = %o, want %o", info.Mode().Perm(), PasswordDirPerm)
	}
}

func TestEnsureSecretsDirSecure_RejectsWrongOwner(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to change directory owner for ownership validation test")
	}

	tmpDir := t.TempDir()
	secretsPath := filepath.Join(tmpDir, "secrets")
	if err := os.MkdirAll(secretsPath, 0o700); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.Chown(secretsPath, 65534, 65534); err != nil {
		t.Fatalf("Chown() error = %v", err)
	}

	if err := ensureSecretsDirSecure(secretsPath); err == nil {
		t.Fatal("expected ownership validation failure")
	}
}

func TestEnsureSecretsDirSecure_RejectsSymlink(t *testing.T) {
	tmpDir := t.TempDir()
	realSecrets := filepath.Join(tmpDir, "real-secrets")
	linkSecrets := filepath.Join(tmpDir, "secrets-link")
	if err := os.MkdirAll(realSecrets, 0o700); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.Symlink(realSecrets, linkSecrets); err != nil {
		t.Fatalf("Symlink() error = %v", err)
	}

	if err := ensureSecretsDirSecure(linkSecrets); err == nil {
		t.Fatal("expected symlink rejection for secrets directory")
	}
}

func TestSecureWriteSecretFile_RejectsSymlinkTarget(t *testing.T) {
	tmpDir := t.TempDir()
	secretsPath := filepath.Join(tmpDir, "secrets")
	targetPath := filepath.Join(tmpDir, "target")
	if err := os.MkdirAll(secretsPath, 0o700); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(targetPath, []byte("old"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	passwordPath := filepath.Join(secretsPath, "repo.password")
	if err := os.Symlink(targetPath, passwordPath); err != nil {
		t.Fatalf("Symlink() error = %v", err)
	}

	if err := secureWriteSecretFile(passwordPath, []byte("new"), PasswordFilePerm); err == nil {
		t.Fatal("expected secure write to fail for symlink target")
	}

	content, err := os.ReadFile(targetPath)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(content) != "old" {
		t.Fatalf("target content mutated through symlink: got %q", string(content))
	}
}

func TestGetRepositoryPassword_VaultFirstFallback(t *testing.T) {
	rc := testRuntimeContext()
	tmpDir := t.TempDir()

	origRead := configReadCandidates
	origWritePath := configWritePath
	origWriteDir := configWriteDir
	origSecrets := secretsDirPath
	origVaultAddr := os.Getenv("VAULT_ADDR")
	origVaultToken := os.Getenv("VAULT_TOKEN")
	t.Cleanup(func() {
		configReadCandidates = origRead
		configWritePath = origWritePath
		configWriteDir = origWriteDir
		secretsDirPath = origSecrets
		_ = os.Setenv("VAULT_ADDR", origVaultAddr)
		_ = os.Setenv("VAULT_TOKEN", origVaultToken)
	})

	configPath := filepath.Join(tmpDir, "backup.yaml")
	configReadCandidates = []string{configPath}
	configWritePath = configPath
	configWriteDir = tmpDir
	secretsDirPath = filepath.Join(tmpDir, "secrets")

	cfg := &Config{
		DefaultRepository: "repo-a",
		Repositories: map[string]Repository{
			"repo-a": {Name: "repo-a", Backend: "local", URL: filepath.Join(tmpDir, "repo-a")},
		},
		Profiles: map[string]Profile{
			"system": {Name: "system", Repository: "repo-a", Paths: []string{tmpDir}},
		},
	}
	if err := SaveConfig(rc, cfg); err != nil {
		t.Fatalf("SaveConfig() error = %v", err)
	}
	if err := storeLocalPassword("repo-a", "fallback-password"); err != nil {
		t.Fatalf("storeLocalPassword() error = %v", err)
	}

	if err := os.Setenv("VAULT_ADDR", "http://127.0.0.1:18200"); err != nil {
		t.Fatalf("Setenv VAULT_ADDR error = %v", err)
	}
	_ = os.Unsetenv("VAULT_TOKEN")

	client, err := NewClient(rc, "repo-a")
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	beforeVaultFailure := readExpvarInt(t, backupPasswordSourceTotal, "vault_failure")
	beforeLocalSuccess := readExpvarInt(t, backupPasswordSourceTotal, "secrets_password_file_success")
	password, err := client.getRepositoryPassword()
	if err != nil {
		t.Fatalf("getRepositoryPassword() error = %v", err)
	}
	if password != "fallback-password" {
		t.Fatalf("password = %q, want fallback-password", password)
	}

	afterVaultFailure := readExpvarInt(t, backupPasswordSourceTotal, "vault_failure")
	afterLocalSuccess := readExpvarInt(t, backupPasswordSourceTotal, "secrets_password_file_success")
	if afterVaultFailure <= beforeVaultFailure {
		t.Fatalf("expected vault_failure to increase, before=%d after=%d", beforeVaultFailure, afterVaultFailure)
	}
	if afterLocalSuccess <= beforeLocalSuccess {
		t.Fatalf("expected secrets_password_file_success to increase, before=%d after=%d", beforeLocalSuccess, afterLocalSuccess)
	}
}

func TestPasswordSourceStructuredTelemetry(t *testing.T) {
	beforeSource := readExpvarInt(t, backupPasswordSourceBySourceTotal, "telemetry_test_source")
	beforeOutcome := readExpvarInt(t, backupPasswordSourceByOutcomeTotal, "success")

	recordPasswordSource("telemetry_test_source", true)

	afterSource := readExpvarInt(t, backupPasswordSourceBySourceTotal, "telemetry_test_source")
	afterOutcome := readExpvarInt(t, backupPasswordSourceByOutcomeTotal, "success")
	if afterSource <= beforeSource {
		t.Fatalf("expected source counter to increase, before=%d after=%d", beforeSource, afterSource)
	}
	if afterOutcome <= beforeOutcome {
		t.Fatalf("expected outcome counter to increase, before=%d after=%d", beforeOutcome, afterOutcome)
	}
}
