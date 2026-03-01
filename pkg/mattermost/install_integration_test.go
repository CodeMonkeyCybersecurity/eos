//go:build integration

package mattermost

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
)

// --- Integration tests (test pyramid: integration, 20% weight) ---
// These tests exercise real filesystem operations but no external services.

func TestInstallWith_DryRun_Integration(t *testing.T) {
	rc := &eos_io.RuntimeContext{Ctx: context.Background()}
	cfg := DefaultInstallConfig()
	cfg.DryRun = true

	ins := noopInstaller()

	// DryRun should succeed even without Docker
	if err := installWith(rc, cfg, ins); err != nil {
		t.Fatalf("dry run should not error: %v", err)
	}
}

func TestPatchEnvInPlace_RealisticEnvExample(t *testing.T) {
	tmpDir := t.TempDir()

	// Realistic env.example matching what Mattermost ships
	envExample := `# Domain of service
DOMAIN=mm.example.com

# Container settings
TZ=UTC

# Postgres settings
POSTGRES_USER=mmuser
POSTGRES_PASSWORD=mmuser_password
POSTGRES_DB=mattermost

# Mattermost settings
MM_BLEVESETTINGS_INDEXDIR=/mattermost/bleve-indexes
MM_SERVICESETTINGS_SITEURL=https://mm.example.com

#MATTERMOST_CONTAINER_READONLY=true

PORT=8065

MM_SQLSETTINGS_MAXIDLECONNS=20
MM_SQLSETTINGS_MAXOPENCONNS=300

MM_SUPPORTSETTINGS_SUPPORTEMAIL=support@example.com
`
	if err := os.WriteFile(filepath.Join(tmpDir, EnvExampleFileName), []byte(envExample), 0644); err != nil {
		t.Fatalf("failed to create env.example: %v", err)
	}

	// Test PatchMattermostEnv directly
	if err := PatchMattermostEnv(tmpDir); err != nil {
		t.Fatalf("PatchMattermostEnv failed: %v", err)
	}

	envPath := filepath.Join(tmpDir, EnvFileName)
	result, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatalf("failed to read .env: %v", err)
	}

	resultStr := string(result)

	if got := extractEnvValue(resultStr, "DOMAIN"); got != "localhost" {
		t.Errorf("DOMAIN should be 'localhost', got %q", got)
	}
	if got := extractEnvValue(resultStr, "TZ"); got != "UTC" {
		t.Errorf("TZ should be 'UTC', got %q", got)
	}
	if got := extractEnvValue(resultStr, "POSTGRES_USER"); got != "mmuser" {
		t.Errorf("POSTGRES_USER should be preserved as 'mmuser', got %q", got)
	}
}

func TestEnsureVolumesWith_Integration(t *testing.T) {
	rc := &eos_io.RuntimeContext{Ctx: context.Background()}

	// Track created directories
	var createdDirs []string
	ins := noopInstaller()
	ins.mkdirAll = func(path string, _ os.FileMode) error {
		createdDirs = append(createdDirs, path)
		return nil
	}

	if err := ensureVolumesWith(rc, ins); err != nil {
		t.Fatalf("ensureVolumesWith failed: %v", err)
	}

	if len(createdDirs) != len(VolumeSubdirs) {
		t.Errorf("expected %d dirs created, got %d", len(VolumeSubdirs), len(createdDirs))
	}
}

func TestInstallWith_FullPipeline_Integration(t *testing.T) {
	rc := &eos_io.RuntimeContext{Ctx: context.Background()}
	cfg := DefaultInstallConfig()
	cfg.PostgresPassword = "integration-test-pass"

	// Track all operations
	var ops []string
	ins := noopInstaller()
	ins.gitClone = func(_, _ string) error {
		ops = append(ops, "clone")
		return nil
	}
	ins.mkdirP = func(_ *eos_io.RuntimeContext, _ string, _ os.FileMode) error {
		ops = append(ops, "mkdir")
		return nil
	}
	ins.copyR = func(_ *eos_io.RuntimeContext, _, _ string) error {
		ops = append(ops, "copy")
		return nil
	}
	ins.readFile = func(_ string) ([]byte, error) {
		return []byte("DOMAIN=x\nPORT=8065\n"), nil
	}
	ins.chown = func(_, _ string) error {
		ops = append(ops, "chown")
		return nil
	}
	ins.composeUp = func(_ *eos_io.RuntimeContext, _ string) error {
		ops = append(ops, "compose")
		return nil
	}

	if err := installWith(rc, cfg, ins); err != nil {
		t.Fatalf("installWith failed: %v", err)
	}

	// Verify operations happened in correct order
	expectedOrder := []string{"clone", "mkdir", "copy", "chown", "compose"}
	if len(ops) != len(expectedOrder) {
		t.Fatalf("expected %d ops, got %d: %v", len(expectedOrder), len(ops), ops)
	}
	for i, expected := range expectedOrder {
		if ops[i] != expected {
			t.Errorf("operation %d: want %q, got %q (full: %v)", i, expected, ops[i], ops)
		}
	}
}

// --- Test helpers ---

func extractEnvValue(content, key string) string {
	for _, line := range strings.Split(content, "\n") {
		if len(line) > 0 && line[0] != '#' {
			if idx := strings.Index(line, "="); idx > 0 {
				if line[:idx] == key {
					return line[idx+1:]
				}
			}
		}
	}
	return ""
}
