//go:build e2e

package mattermost

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// --- E2E smoke tests (test pyramid: e2e, 10% weight) ---
// These tests verify the CLI command compiles and shows help.
// They do NOT deploy actual containers.

// repoRoot returns the git repository root for reliable path resolution.
func repoRoot(t *testing.T) string {
	t.Helper()
	// Walk up from this file's directory to find go.mod
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot determine test file path")
	}
	dir := filepath.Dir(file)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("cannot find repo root (no go.mod found)")
		}
		dir = parent
	}
}

func TestCreateMattermostCommand_Help(t *testing.T) {
	root := repoRoot(t)
	cmd := exec.Command("go", "run", filepath.Join(root, "cmd"), "create", "mattermost", "--help")
	cmd.Dir = root
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("'eos create mattermost --help' failed: %v\nOutput: %s", err, output)
	}

	outputStr := string(output)
	if len(outputStr) == 0 {
		t.Error("help output should not be empty")
	}
	if !strings.Contains(outputStr, "mattermost") {
		t.Error("help output should mention 'mattermost'")
	}
}

func TestCreateMattermostCommand_DryRun_NonRoot(t *testing.T) {
	root := repoRoot(t)
	cmd := exec.Command("go", "run", filepath.Join(root, "cmd"), "create", "mattermost", "--dry-run")
	cmd.Dir = root
	output, err := cmd.CombinedOutput()

	if err == nil {
		t.Log("command succeeded (likely running as root in CI)")
		return
	}

	outputStr := string(output)
	if len(outputStr) == 0 {
		t.Error("error output should explain the failure")
	}
}
