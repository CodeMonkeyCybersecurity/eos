//go:build e2e_full

// End-to-End FULL Test: Vault Lifecycle
// Tests complete Vault workflow with REAL SYSTEM OPERATIONS
// WARNING: This test MODIFIES the system - run only in isolated test environment
package full

import (
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/test/e2e"
)

// TestFull_VaultLifecycle tests the complete Vault lifecycle with real operations
//
// Workflow:
// 1. eos create vault → Vault installed and running
// 2. eos read vault status → Verify health
// 3. eos update vault --fix → Drift correction
// 4. eos read vault status → Verify still healthy
// 5. eos delete vault → Clean removal
//
// This test verifies:
// - Service installation works end-to-end
// - Status reporting is accurate
// - Drift correction doesn't break service
// - Cleanup is thorough
//
// REQUIREMENTS:
// - Root privileges (sudo)
// - Fresh Ubuntu 24.04 LTS installation
// - Isolated test environment (VM or container)
// - Network connectivity
// - 20GB+ disk space
func TestFull_VaultLifecycle(t *testing.T) {
	suite := e2e.NewE2ETestSuite(t, "vault-lifecycle-full")

	// Full E2E tests are slow - skip in short mode
	suite.SkipIfShort("Vault full lifecycle test is slow (10-15 minutes)")

	// Vault operations require root
	suite.RequireRoot("Vault installation requires root privileges")

	// Skip on macOS (Vault requires Linux)
	if runtime.GOOS == "darwin" {
		t.Skip("Skipping Vault full E2E test on macOS (requires Linux)")
	}

	// Verify test environment is isolated
	if os.Getenv("EOS_E2E_FULL_APPROVED") != "true" {
		t.Skip("Skipping full E2E test - set EOS_E2E_FULL_APPROVED=true to run destructive tests")
	}

	// Cleanup: Delete Vault if test fails midway
	defer func() {
		suite.Logger.Info("Running E2E test cleanup")
		result := suite.RunCommand("delete", "vault", "--force")
		if result.ExitCode == 0 {
			suite.Logger.Info("Cleanup: Vault deleted successfully")
		} else {
			suite.Logger.Info("Cleanup: Vault not found or already deleted")
		}
		suite.RunCleanup()
	}()

	// ========================================
	// PHASE 1: Create Vault
	// ========================================
	t.Run("Phase1_CreateVault", func(t *testing.T) {
		suite.Logger.Info("Phase 1: Creating Vault cluster")

		result := suite.RunWithTimeout(10*time.Minute, "create", "vault")
		result.AssertSuccess(t)
		result.AssertContains(t, "Vault installed successfully")

		suite.Logger.Info("Phase 1: Vault created successfully")
	})

	// ========================================
	// PHASE 2: Verify Vault Status
	// ========================================
	t.Run("Phase2_VerifyVaultStatus", func(t *testing.T) {
		suite.Logger.Info("Phase 2: Verifying Vault status")

		// Wait for Vault to be ready
		suite.WaitForCondition(func() bool {
			result := suite.RunCommand("read", "vault", "status")
			return result.ExitCode == 0
		}, 2*time.Minute, "Vault becomes healthy")

		// Verify status output
		result := suite.RunCommand("read", "vault", "status")
		result.AssertSuccess(t)
		result.AssertContains(t, "Vault")

		// Should show unsealed status
		result.AssertContains(t, "unsealed")

		// Should show cluster initialized
		result.AssertContains(t, "initialized")

		suite.Logger.Info("Phase 2: Vault is healthy and unsealed")
	})

	// ========================================
	// PHASE 3: Simulate Drift and Fix
	// ========================================
	t.Run("Phase3_FixDrift", func(t *testing.T) {
		suite.Logger.Info("Phase 3: Testing drift correction")

		// Create drift by modifying Vault config file
		// NOTE: This is a controlled drift - we'll change permissions
		configFile := "/etc/vault.d/vault.hcl"

		// Check original permissions
		origInfo, err := os.Stat(configFile)
		if err != nil {
			t.Fatalf("Failed to stat Vault config: %v", err)
		}
		origPerm := origInfo.Mode().Perm()

		// Introduce drift: change permissions
		err = os.Chmod(configFile, 0777) // Intentionally wrong
		if err != nil {
			t.Fatalf("Failed to introduce drift: %v", err)
		}

		suite.Logger.Info("Drift introduced: changed config file permissions to 0777")

		// Run fix
		result := suite.RunCommand("update", "vault", "--fix")
		result.AssertSuccess(t)
		result.AssertContains(t, "Fixed")

		// Verify permissions restored
		fixedInfo, err := os.Stat(configFile)
		if err != nil {
			t.Fatalf("Failed to stat config after fix: %v", err)
		}
		fixedPerm := fixedInfo.Mode().Perm()

		if fixedPerm != origPerm {
			t.Errorf("Permissions not restored correctly: want %o, got %o", origPerm, fixedPerm)
		}

		suite.Logger.Info("Phase 3: Drift corrected successfully")
	})

	// ========================================
	// PHASE 4: Verify Health After Fix
	// ========================================
	t.Run("Phase4_VerifyHealthAfterFix", func(t *testing.T) {
		suite.Logger.Info("Phase 4: Verifying Vault health after drift fix")

		result := suite.RunCommand("read", "vault", "status")
		result.AssertSuccess(t)
		result.AssertContains(t, "unsealed")

		// Vault should still be operational
		result.AssertContains(t, "initialized")

		suite.Logger.Info("Phase 4: Vault remains healthy after fix")
	})

	// ========================================
	// PHASE 5: Delete Vault
	// ========================================
	t.Run("Phase5_DeleteVault", func(t *testing.T) {
		suite.Logger.Info("Phase 5: Deleting Vault cluster")

		result := suite.RunCommand("delete", "vault", "--force")
		result.AssertSuccess(t)
		result.AssertContains(t, "deleted")

		suite.Logger.Info("Phase 5: Vault deleted successfully")
	})

	// ========================================
	// PHASE 6: Verify Clean Removal
	// ========================================
	t.Run("Phase6_VerifyCleanRemoval", func(t *testing.T) {
		suite.Logger.Info("Phase 6: Verifying clean removal")

		// Verify Vault binary removed
		if _, err := os.Stat("/usr/local/bin/vault"); !os.IsNotExist(err) {
			t.Errorf("Vault binary still exists after deletion")
		}

		// Verify config directory removed
		if _, err := os.Stat("/etc/vault.d"); !os.IsNotExist(err) {
			t.Errorf("Vault config directory still exists after deletion")
		}

		// Verify data directory removed
		if _, err := os.Stat("/opt/vault"); !os.IsNotExist(err) {
			t.Errorf("Vault data directory still exists after deletion")
		}

		// Verify systemd unit removed
		result := suite.RunCommand("systemctl", "status", "vault.service")
		result.AssertFails(t) // Should fail because service doesn't exist
		result.AssertContains(t, "not-found")

		suite.Logger.Info("Phase 6: Vault completely removed")
	})

	suite.Logger.Info("Vault full lifecycle E2E test completed successfully")
}

// TestFull_VaultLifecycle_WithErrors tests error handling in real Vault lifecycle
func TestFull_VaultLifecycle_WithErrors(t *testing.T) {
	suite := e2e.NewE2ETestSuite(t, "vault-lifecycle-errors-full")
	suite.SkipIfShort("Vault error handling test is slow")
	suite.RequireRoot("Vault installation requires root privileges")

	if os.Getenv("EOS_E2E_FULL_APPROVED") != "true" {
		t.Skip("Skipping full E2E test - set EOS_E2E_FULL_APPROVED=true")
	}

	defer func() {
		// Cleanup
		suite.RunCommand("delete", "vault", "--force")
		suite.RunCleanup()
	}()

	// ========================================
	// TEST: Create Vault Twice (Should Fail)
	// ========================================
	t.Run("CreateVaultTwice_ShouldFail", func(t *testing.T) {
		suite.Logger.Info("Testing: Create Vault twice should fail")

		// First creation should succeed
		result1 := suite.RunWithTimeout(10*time.Minute, "create", "vault")
		result1.AssertSuccess(t)

		// Second creation should fail
		result2 := suite.RunCommand("create", "vault")
		result2.AssertFails(t)
		result2.AssertContains(t, "already installed")

		suite.Logger.Info("Test passed: Duplicate creation correctly rejected")
	})

	// ========================================
	// TEST: Delete Non-Existent Vault
	// ========================================
	t.Run("DeleteNonExistent_HandlesGracefully", func(t *testing.T) {
		suite.Logger.Info("Testing: Delete non-existent Vault")

		// First delete the existing Vault from previous test
		suite.RunCommand("delete", "vault", "--force")

		// Try to delete again - should handle gracefully
		result := suite.RunCommand("delete", "vault", "--force")

		// Should either succeed (idempotent) or give clear message
		if result.ExitCode != 0 {
			result.AssertContains(t, "not found")
		}

		suite.Logger.Info("Test passed: Non-existent deletion handled gracefully")
	})
}

// TestFull_VaultCluster tests Vault cluster operations
func TestFull_VaultCluster(t *testing.T) {
	suite := e2e.NewE2ETestSuite(t, "vault-cluster-full")
	suite.SkipIfShort("Vault cluster test is slow")
	suite.RequireRoot("Vault cluster operations require root")

	if os.Getenv("EOS_E2E_FULL_APPROVED") != "true" {
		t.Skip("Skipping full E2E test - set EOS_E2E_FULL_APPROVED=true")
	}

	defer func() {
		suite.RunCommand("delete", "vault", "--force")
		suite.RunCleanup()
	}()

	// Create Vault first
	result := suite.RunWithTimeout(10*time.Minute, "create", "vault")
	result.AssertSuccess(t)

	t.Run("ListRaftPeers", func(t *testing.T) {
		result := suite.RunCommand("update", "vault", "cluster", "raft", "list-peers")
		result.AssertSuccess(t)
		// Should show at least this node
		result.AssertContains(t, "node")
	})

	t.Run("AutopilotStatus", func(t *testing.T) {
		result := suite.RunCommand("update", "vault", "cluster", "autopilot", "state")
		result.AssertSuccess(t)
		// Should show autopilot configuration
		result.AssertContains(t, "Healthy")
	})
}
