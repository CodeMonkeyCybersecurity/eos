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

func TestSmoke_BackupChatsRejectsConflictingModes(t *testing.T) {
	suite := e2e.NewE2ETestSuite(t, "backup-chats-flag-validation-smoke")

	result := suite.RunCommand("backup", "chats", "--setup", "--prune")
	result.AssertFails(t)
	result.AssertContains(t, "if any flags in the group [setup prune list] are set")
}
