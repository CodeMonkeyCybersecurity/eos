//go:build e2e_smoke

package smoke

import (
	"strings"
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/test/e2e"
)

func TestSmoke_BackupRepositoryResolution(t *testing.T) {
	suite := e2e.NewE2ETestSuite(t, "backup-repository-resolution-smoke")

	t.Run("VerifyRepositoryMissing_UsesSharedResolver", func(t *testing.T) {
		result := suite.RunCommand("backup", "verify", "repository", "--repo", "__missing_repo__")
		result.AssertFails(t)
		assertContainsAny(t, result, []string{
			"repository \"__missing_repo__\" not found in configuration",
			"permission denied reading config file",
		})
	})

	t.Run("ListBackupsMissingRepository_UsesSharedResolver", func(t *testing.T) {
		result := suite.RunCommand("list", "backups", "--repo", "__missing_repo__")
		result.AssertFails(t)
		assertContainsAny(t, result, []string{
			"repository \"__missing_repo__\" not found in configuration",
			"permission denied reading config file",
		})
	})

	t.Run("QuickBackupPath_ProducesActionableOutput", func(t *testing.T) {
		result := suite.RunCommand("backup", ".", "--dry-run")
		// Command may succeed (exit 0) or fail depending on environment.
		// In CI without restic/config, it may exit 0 with warnings or fail.
		// Verify it produces some output (not silent).
		combined := result.Stdout + result.Stderr
		if len(combined) == 0 {
			t.Fatal("expected command to produce output, got empty stdout+stderr")
		}
	})
}

func assertContainsAny(t *testing.T, result *e2e.CommandResult, options []string) {
	t.Helper()
	combined := result.Stdout + result.Stderr
	for _, option := range options {
		if strings.Contains(combined, option) {
			return
		}
	}
	t.Fatalf("expected output to contain one of %q\nstdout:\n%s\nstderr:\n%s", options, result.Stdout, result.Stderr)
}
