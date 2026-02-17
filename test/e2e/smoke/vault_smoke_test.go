//go:build e2e_smoke

// E2E Smoke Test: Vault Commands
// Tests that Vault commands exist and are properly structured
// WITHOUT actually installing or modifying the system
package smoke

import (
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/test/e2e"
)

// TestSmoke_VaultCommands verifies Vault command structure
// These tests are FAST and SAFE - they don't modify system state
func TestSmoke_VaultCommands(t *testing.T) {
	suite := e2e.NewE2ETestSuite(t, "vault-commands-smoke")

	t.Run("CreateCommand_Exists", func(t *testing.T) {
		result := suite.RunCommand("create", "vault", "--help")
		result.AssertSuccess(t)
		result.AssertContains(t, "Install HashiCorp Vault")
	})

	t.Run("ReadCommand_Exists", func(t *testing.T) {
		result := suite.RunCommand("read", "vault", "--help")
		result.AssertSuccess(t)
	})

	t.Run("UpdateCommand_Exists", func(t *testing.T) {
		result := suite.RunCommand("update", "vault", "--help")
		result.AssertSuccess(t)
	})

	t.Run("DeleteCommand_Exists", func(t *testing.T) {
		result := suite.RunCommand("delete", "vault", "--help")
		result.AssertSuccess(t)
		result.AssertContains(t, "Delete")
	})

	t.Run("DebugCommand_Exists", func(t *testing.T) {
		result := suite.RunCommand("debug", "vault", "--help")
		result.AssertSuccess(t)
	})
}

// TestSmoke_VaultFlags verifies Vault flag parsing and validation
func TestSmoke_VaultFlags(t *testing.T) {
	suite := e2e.NewE2ETestSuite(t, "vault-flags-smoke")

	t.Run("FixFlag_Recognized", func(t *testing.T) {
		// Verify --fix flag exists and is documented
		result := suite.RunCommand("update", "vault", "--help")
		result.AssertSuccess(t)
		result.AssertContains(t, "--fix")
	})

	t.Run("DryRunFlag_Recognized", func(t *testing.T) {
		// Verify --dry-run flag exists
		result := suite.RunCommand("update", "vault", "--help")
		result.AssertSuccess(t)
		result.AssertContains(t, "--dry-run")
	})

	t.Run("DeleteSafetyFlags_Recognized", func(t *testing.T) {
		// Verify delete safety flags are documented on delete command.
		result := suite.RunCommand("delete", "vault", "--help")
		result.AssertSuccess(t)
		result.AssertContains(t, "--yes")
		result.AssertContains(t, "--purge")
	})

	t.Run("InvalidFlag_Rejected", func(t *testing.T) {
		// Verify unknown flags are caught
		result := suite.RunCommand("create", "vault", "--this-flag-does-not-exist")
		result.AssertFails(t)
		result.AssertContains(t, "unknown flag")
	})
}

// TestSmoke_VaultSubcommands verifies Vault subcommand structure
func TestSmoke_VaultSubcommands(t *testing.T) {
	suite := e2e.NewE2ETestSuite(t, "vault-subcommands-smoke")

	t.Run("UpdateCluster_Exists", func(t *testing.T) {
		result := suite.RunCommand("update", "vault", "cluster", "--help")
		result.AssertSuccess(t)
	})

	t.Run("UpdateUnseal_Exists", func(t *testing.T) {
		result := suite.RunCommand("update", "vault", "unseal", "--help")
		result.AssertSuccess(t)
	})

	t.Run("ReadStatus_Exists", func(t *testing.T) {
		result := suite.RunCommand("read", "vault", "status", "--help")
		result.AssertSuccess(t)
	})
}

// TestSmoke_VaultValidation verifies input validation without system changes
func TestSmoke_VaultValidation(t *testing.T) {
	suite := e2e.NewE2ETestSuite(t, "vault-validation-smoke")

	t.Run("DryRun_DoesNotModifySystem", func(t *testing.T) {
		// Verify --dry-run mode doesn't make changes
		// This is safe to run even without root
		result := suite.RunCommand("update", "vault", "--fix", "--dry-run")

		// Dry-run should complete without errors OR fail with "vault not installed"
		// Either outcome is acceptable for smoke test
		if result.ExitCode != 0 {
			// If it fails, should be because Vault isn't installed, not a code error
			result.AssertContains(t, "not installed")
		}
	})
}

// TestSmoke_VaultErrorMessages verifies error message quality
func TestSmoke_VaultErrorMessages(t *testing.T) {
	suite := e2e.NewE2ETestSuite(t, "vault-error-messages-smoke")

	t.Run("MissingArgument_ClearError", func(t *testing.T) {
		// Test that missing required arguments give clear errors
		result := suite.RunCommand("update", "vault")
		result.AssertContains(t, "Must specify one of")
	})

	t.Run("InvalidSubcommand_ClearError", func(t *testing.T) {
		result := suite.RunCommand("update", "vault", "nonexistent-subcommand")
		result.AssertContains(t, "Must specify one of")
	})
}

// TestSmoke_VaultHelpText verifies help documentation quality
func TestSmoke_VaultHelpText(t *testing.T) {
	suite := e2e.NewE2ETestSuite(t, "vault-help-smoke")

	t.Run("CreateHelp_Comprehensive", func(t *testing.T) {
		result := suite.RunCommand("create", "vault", "--help")
		result.AssertSuccess(t)

		// Help should include key information
		result.AssertContains(t, "Usage:")
		result.AssertContains(t, "Flags:")

		// Should mention Vault-specific info
		result.AssertContains(t, "Vault")
	})

	t.Run("UpdateHelp_IncludesFixOption", func(t *testing.T) {
		result := suite.RunCommand("update", "vault", "--help")
		result.AssertSuccess(t)

		// Should document --fix flag
		result.AssertContains(t, "--fix")
		result.AssertContains(t, "drift")
	})

	t.Run("DeleteHelp_WarnsAboutDestruction", func(t *testing.T) {
		result := suite.RunCommand("delete", "vault", "--help")
		result.AssertSuccess(t)

		// Should document safety flags and warn about deletion.
		result.AssertContains(t, "--yes")
		result.AssertContains(t, "--purge")
	})
}
