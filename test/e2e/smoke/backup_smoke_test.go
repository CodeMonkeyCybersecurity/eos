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

	t.Run("QuickBackupPath_ProducesActionableFailure", func(t *testing.T) {
		result := suite.RunCommand("backup", ".", "--dry-run")
		result.AssertFails(t)
		assertContainsAny(t, result, []string{
			"permission denied reading config file",
			"no repositories configured",
			"Restic is not installed",
		})
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
