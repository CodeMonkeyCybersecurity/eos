package backup

import (
	"context"
	"path/filepath"
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
