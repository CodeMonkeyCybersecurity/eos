//go:build e2e_smoke

package smoke

import (
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/test/e2e"
)

func TestSmoke_BackupRepositoryResolution(t *testing.T) {
	suite := e2e.NewE2ETestSuite(t, "backup-repository-resolution-smoke")

	t.Run("VerifyRepositoryMissing_UsesSharedResolver", func(t *testing.T) {
		result := suite.RunCommand("backup", "verify", "repository", "--repo", "__missing_repo__")
		result.AssertFails(t)
		result.AssertContains(t, "repository \"__missing_repo__\" not found in configuration")
	})

	t.Run("ListBackupsMissingRepository_UsesSharedResolver", func(t *testing.T) {
		result := suite.RunCommand("list", "backups", "--repo", "__missing_repo__")
		result.AssertFails(t)
		result.AssertContains(t, "repository \"__missing_repo__\" not found in configuration")
	})
}
