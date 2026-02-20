package backup

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"go.uber.org/zap"
)

func TestRepositoryResolutionAndPasswordFallbackIntegration(t *testing.T) {
	rc := &eos_io.RuntimeContext{Ctx: context.Background(), Log: zap.NewNop()}
	tmpDir := t.TempDir()

	origRead := configReadCandidates
	origWritePath := configWritePath
	origWriteDir := configWriteDir
	origSecretsDir := secretsDirPath
	t.Cleanup(func() {
		configReadCandidates = origRead
		configWritePath = origWritePath
		configWriteDir = origWriteDir
		secretsDirPath = origSecretsDir
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
			"repo-b": {Name: "repo-b", Backend: "local", URL: filepath.Join(tmpDir, "repo-b")},
		},
		Profiles: map[string]Profile{
			"system": {
				Name:       "system",
				Repository: "repo-a",
				Paths:      []string{tmpDir},
			},
		},
	}

	if err := SaveConfig(rc, cfg); err != nil {
		t.Fatalf("SaveConfig() error = %v", err)
	}

	repoName, err := ResolveRepositoryName(rc, "")
	if err != nil {
		t.Fatalf("ResolveRepositoryName() error = %v", err)
	}
	if repoName != "repo-a" {
		t.Fatalf("resolved repo = %q, want repo-a", repoName)
	}

	if err := storeLocalPassword("repo-a", "integration-password"); err != nil {
		t.Fatalf("storeLocalPassword() error = %v", err)
	}

	client, err := NewClient(rc, repoName)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	password, err := client.getRepositoryPassword()
	if err != nil {
		t.Fatalf("getRepositoryPassword() error = %v", err)
	}
	if password != "integration-password" {
		t.Fatalf("password = %q, want integration-password", password)
	}
}

func TestIntegrationLoadConfigPermissionDenied(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permission-denied integration test requires non-root execution")
	}

	rc := &eos_io.RuntimeContext{Ctx: context.Background(), Log: zap.NewNop()}
	tmpDir := t.TempDir()

	origRead := configReadCandidates
	t.Cleanup(func() {
		configReadCandidates = origRead
	})

	canonicalPath := filepath.Join(tmpDir, "backup.yaml")
	legacyPath := filepath.Join(tmpDir, "backup", "config.yaml")
	configReadCandidates = []string{canonicalPath, legacyPath}

	content := []byte(`
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
	if err := os.WriteFile(legacyPath, content, 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := os.WriteFile(canonicalPath, content, 0o600); err != nil {
		t.Fatalf("WriteFile() canonical error = %v", err)
	}
	if err := os.Chmod(canonicalPath, 0); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(canonicalPath, 0o600) })

	_, err := LoadConfig(rc)
	if err == nil {
		t.Fatal("expected permission denied error")
	}
	if !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("expected permission denied error, got %v", err)
	}
}

func TestIntegrationPasswordLookup_SkipWizardWhenConfigured(t *testing.T) {
	rc := &eos_io.RuntimeContext{Ctx: context.Background(), Log: zap.NewNop()}
	tmpDir := t.TempDir()

	origRead := configReadCandidates
	origWritePath := configWritePath
	origWriteDir := configWriteDir
	origSecretsDir := secretsDirPath
	origSkip := os.Getenv("RESTIC_PASSWORD_SKIP_WIZARD")
	t.Cleanup(func() {
		configReadCandidates = origRead
		configWritePath = origWritePath
		configWriteDir = origWriteDir
		secretsDirPath = origSecretsDir
		_ = os.Setenv("RESTIC_PASSWORD_SKIP_WIZARD", origSkip)
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
	if err := os.Setenv("RESTIC_PASSWORD_SKIP_WIZARD", "1"); err != nil {
		t.Fatalf("Setenv() error = %v", err)
	}

	client, err := NewClient(rc, "repo-a")
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	password, err := client.getRepositoryPassword()
	if err == nil {
		t.Fatalf("expected missing password error, got password=%q", password)
	}
	if password != "" {
		t.Fatalf("expected empty password result, got %q", password)
	}
}
