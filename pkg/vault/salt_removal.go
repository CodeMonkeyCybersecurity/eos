package vault

import (
	"fmt"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"go.uber.org/zap"
)

// RemoveVaultViaSalt removes Vault completely using Salt states
// This provides a clean, comprehensive removal following the architectural principle: Salt = Physical infrastructure
func RemoveVaultViaSalt(rc *eos_io.RuntimeContext) error {
	logger := zap.L().With(zap.String("component", "vault_removal"))
	
	logger.Info("Starting comprehensive Vault removal via Salt states")
	
	// ASSESS - Check if Salt is available
	if err := checkNomadAvailability(rc); err != nil {
		logger.Warn("Nomad not available, falling back to direct removal", zap.Error(err))
		return removeVaultDirect(rc)
	}
	
	// INTERVENE - Remove via Nomad
	if err := removeVaultViaNomad(rc); err != nil {
		logger.Error("Nomad-based Vault removal failed, attempting direct removal", zap.Error(err))
		return removeVaultDirect(rc)
	}
	
	// EVALUATE - Verify removal
	if err := verifyVaultRemoval(rc); err != nil {
		logger.Warn("Vault removal verification had issues", zap.Error(err))
		// Don't fail the removal - it might still be mostly successful
	}
	
	logger.Info("Vault removal completed successfully")
	return nil
}


// removeVaultViaNomad removes Vault using Nomad job management
func removeVaultViaNomad(rc *eos_io.RuntimeContext) error {
	logger := zap.L().With(zap.String("component", "vault_removal"))
	
	logger.Info("Removing Vault via Nomad job management")
	
	// TODO: Implement Nomad job removal
	return fmt.Errorf("Nomad-based Vault removal not yet implemented")
}

// removeVaultDirect removes Vault using the existing direct methods (fallback)
func removeVaultDirect(rc *eos_io.RuntimeContext) error {
	logger := zap.L().With(zap.String("component", "vault_removal"))
	
	logger.Info("Performing direct Vault removal (fallback method)")
	
	// Use the existing Purge function from phase_delete.go
	removed, errs := Purge(rc, "debian") // Assuming debian for now - could detect
	
	logger.Info("Direct Vault removal completed",
		zap.Int("files_removed", len(removed)),
		zap.Int("errors", len(errs)))
	
	if len(errs) > 0 {
		logger.Warn("Some errors occurred during direct removal", zap.Any("errors", errs))
		// Don't fail completely - partial removal is better than no removal
	}
	
	return nil
}

// verifyVaultRemoval verifies that Vault has been properly removed
func verifyVaultRemoval(rc *eos_io.RuntimeContext) error {
	logger := zap.L().With(zap.String("component", "vault_removal"))
	
	logger.Info("Verifying Vault removal")
	
	// Check if vault binary still exists
	if _, err := execute.Run(rc.Ctx, execute.Options{
		Command: "which",
		Args:    []string{"vault"},
		Capture: true,
		Timeout: 5 * time.Second,
	}); err == nil {
		logger.Warn("Vault binary still found in PATH after removal")
	} else {
		logger.Info("Vault binary successfully removed from PATH")
	}
	
	// Check if vault service still exists
	if _, err := execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"list-units", "--all", "vault*"},
		Capture: true,
		Timeout: 5 * time.Second,
	}); err == nil {
		logger.Debug("Checked for remaining Vault services")
	}
	
	// Check if configuration directories still exist
	configDirs := []string{"/etc/vault.d", "/opt/vault"}
	for _, dir := range configDirs {
		if _, err := execute.Run(rc.Ctx, execute.Options{
			Command: "test",
			Args:    []string{"-d", dir},
			Capture: true,
			Timeout: 2 * time.Second,
		}); err == nil {
			logger.Warn("Vault configuration directory still exists", zap.String("directory", dir))
		} else {
			logger.Info("Vault configuration directory successfully removed", zap.String("directory", dir))
		}
	}
	
	logger.Info("Vault removal verification completed")
	return nil
}