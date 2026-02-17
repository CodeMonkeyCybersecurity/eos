package backup

import (
	"context"
	"errors"
	"expvar"
	"fmt"
	"os"
	"path/filepath"
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

	if err := SaveConfig(rc, cfg); err != nil {
		t.Fatalf("SaveConfig() error = %v", err)
	}

	if _, err := os.Stat(canonicalPath); err != nil {
		t.Fatalf("canonical config file not written: %v", err)
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
