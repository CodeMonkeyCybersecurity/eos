//go:build e2e_smoke

package smoke

import "testing"

import "github.com/CodeMonkeyCybersecurity/eos/test/e2e"

func TestSmoke_BackupChatsDryRun(t *testing.T) {
	suite := e2e.NewE2ETestSuite(t, "backup-chats-dryrun-smoke")

	result := suite.RunCommand("backup", "chats", "--dry-run")
	result.AssertSuccess(t)
	result.AssertContains(t, "DRY RUN")
}
