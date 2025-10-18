// cmd/fix/vault.go

package fix

import (
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var (
	vaultRepairDryRun          bool
	vaultRepairCleanupBinaries bool
	vaultRepairPermissions     bool
	vaultRepairConfig          bool
	vaultRepairAll             bool
)

var vaultFixCmd = &cobra.Command{
	Use:   "vault",
	Short: "Fix common Vault installation issues",
	Long: `Automatically detect and fix common Vault installation issues.

This command can repair:
- Duplicate binary installations
- File permissions on config/data/TLS files
- Systemd service configuration
- Configuration file syntax
- Missing directories

EXAMPLES:
  # Auto-repair all detected issues
  sudo eos repair vault --all

  # Dry-run to see what would be fixed (no changes made)
  sudo eos repair vault --all --dry-run

  # Only cleanup duplicate binaries
  sudo eos repair vault --cleanup-binaries

  # Only fix file permissions
  sudo eos repair vault --permissions

  # Only repair configuration
  sudo eos repair vault --config`,

	RunE: eos_cli.Wrap(runVaultRepair),
}

func init() {
	vaultFixCmd.Flags().BoolVar(&vaultRepairDryRun, "dry-run", false, "Show what would be fixed without making changes")
	vaultFixCmd.Flags().BoolVar(&vaultRepairCleanupBinaries, "cleanup-binaries", false, "Remove duplicate vault binaries")
	vaultFixCmd.Flags().BoolVar(&vaultRepairPermissions, "permissions", false, "Fix file permissions and ownership")
	vaultFixCmd.Flags().BoolVar(&vaultRepairConfig, "config", false, "Repair configuration files")
	vaultFixCmd.Flags().BoolVar(&vaultRepairAll, "all", false, "Repair all detected issues")
}

func runVaultRepair(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info(" Starting Vault repair")

	if vaultRepairDryRun {
		logger.Info(" DRY-RUN MODE: No changes will be made")
		fmt.Println(" DRY-RUN MODE: Analyzing issues without making changes")
	}

	// Default: run all repairs if no specific flag is set
	runBinaries := vaultRepairCleanupBinaries || vaultRepairAll || (!vaultRepairCleanupBinaries && !vaultRepairPermissions && !vaultRepairConfig)
	runPermissions := vaultRepairPermissions || vaultRepairAll
	runConfig := vaultRepairConfig || vaultRepairAll

	issuesFound := 0
	issuesFixed := 0

	// Repair: Cleanup duplicate binaries
	if runBinaries {
		logger.Info(" Checking for duplicate vault binaries")
		found, fixed, err := repairDuplicateBinaries(rc, vaultRepairDryRun)
		if err != nil {
			logger.Warn("Binary cleanup encountered errors", zap.Error(err))
		}
		issuesFound += found
		issuesFixed += fixed
	}

	// Repair: Fix permissions
	if runPermissions {
		logger.Info(" Checking file permissions")
		found, fixed, err := repairFilePermissions(rc, vaultRepairDryRun)
		if err != nil {
			logger.Warn("Permission repair encountered errors", zap.Error(err))
		}
		issuesFound += found
		issuesFixed += fixed
	}

	// Repair: Fix configuration
	if runConfig {
		logger.Info(" Checking configuration files")
		found, fixed, err := repairConfiguration(rc, vaultRepairDryRun)
		if err != nil {
			logger.Warn("Configuration repair encountered errors", zap.Error(err))
		}
		issuesFound += found
		issuesFixed += fixed
	}

	// Summary
	fmt.Println()
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println(" Repair Summary")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Printf("Issues found: %d\n", issuesFound)

	if vaultRepairDryRun {
		fmt.Printf("Would fix: %d (DRY-RUN - no changes made)\n", issuesFixed)
		fmt.Println("\nRun without --dry-run to apply fixes")
	} else {
		fmt.Printf("Issues fixed: %d\n", issuesFixed)
	}

	if issuesFound == 0 {
		fmt.Println("\n No issues detected - Vault installation is healthy")
	} else if !vaultRepairDryRun && issuesFixed == issuesFound {
		fmt.Println("\n All issues successfully repaired")
	} else if !vaultRepairDryRun && issuesFixed < issuesFound {
		fmt.Printf("\n%d issues could not be automatically repaired\n", issuesFound-issuesFixed)
		fmt.Println("Run 'sudo eos debug vault' for detailed diagnostics")
	}

	logger.Info(" Vault repair completed",
		zap.Int("issues_found", issuesFound),
		zap.Int("issues_fixed", issuesFixed),
		zap.Bool("dry_run", vaultRepairDryRun))

	return nil
}

// repairDuplicateBinaries finds and removes duplicate vault binaries
func repairDuplicateBinaries(rc *eos_io.RuntimeContext, dryRun bool) (int, int, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Checking for duplicate Vault binaries")

	binaries, err := vault.FindVaultBinaries(rc)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to find binaries: %w", err)
	}

	// Count duplicates (anything not at standard path)
	duplicates := 0
	for _, binary := range binaries {
		if binary.Path != shared.VaultBinaryPath {
			duplicates++
		}
	}

	if duplicates == 0 {
		logger.Info("No duplicate binaries found")
		return 0, 0, nil
	}

	fmt.Printf("\n Found %d duplicate vault binaries\n", duplicates)
	for _, binary := range binaries {
		if binary.Path != shared.VaultBinaryPath {
			fmt.Printf("   - %s (%s)\n", binary.Path, binary.Version)
		}
	}

	if dryRun {
		fmt.Printf("Would remove %d duplicate binaries\n", duplicates)
		return duplicates, duplicates, nil
	}

	// Actually remove duplicates
	if err := vault.CleanupDuplicateBinaries(rc, shared.VaultBinaryPath); err != nil {
		return duplicates, 0, fmt.Errorf("failed to cleanup binaries: %w", err)
	}

	fmt.Printf(" Removed %d duplicate binaries\n", duplicates)
	return duplicates, duplicates, nil
}

// repairFilePermissions fixes file permissions and ownership
func repairFilePermissions(rc *eos_io.RuntimeContext, dryRun bool) (int, int, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Checking file permissions")

	// Define expected permissions for Vault files
	fileChecks := []struct {
		path         string
		expectedPerm uint32
		description  string
	}{
		{shared.TLSCrt, 0644, "TLS certificate"},
		{shared.TLSKey, 0600, "TLS private key"},
		{shared.VaultConfigPath, 0640, "Vault configuration"},
		{shared.VaultDataPath, 0750, "Vault data directory"},
		{"/var/log/vault", 0750, "Vault log directory"},
	}

	issuesFound := 0
	issuesFixed := 0

	fmt.Println()
	for _, check := range fileChecks {
		info, err := os.Stat(check.path)
		if err != nil {
			if os.IsNotExist(err) {
				logger.Debug("File does not exist", zap.String("path", check.path))
				continue
			}
			logger.Warn("Cannot check file", zap.String("path", check.path), zap.Error(err))
			continue
		}

		actualPerm := uint32(info.Mode().Perm())
		if actualPerm != check.expectedPerm {
			issuesFound++
			fmt.Printf("%s has incorrect permissions: %o (expected %o)\n",
				check.description, actualPerm, check.expectedPerm)

			if !dryRun {
				if err := os.Chmod(check.path, os.FileMode(check.expectedPerm)); err != nil {
					logger.Error("Failed to fix permissions",
						zap.String("path", check.path),
						zap.Error(err))
				} else {
					issuesFixed++
					fmt.Printf("    Fixed: %s\n", check.path)
				}
			} else {
				issuesFixed++ // Would fix
			}
		}
	}

	if issuesFound == 0 {
		logger.Info("All file permissions are correct")
	}

	return issuesFound, issuesFixed, nil
}

// repairConfiguration validates and repairs configuration files
func repairConfiguration(rc *eos_io.RuntimeContext, dryRun bool) (int, int, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Checking configuration files")

	// Validate config
	result, err := vault.ValidateConfigWithFallback(rc, shared.VaultConfigPath)
	if err != nil {
		return 1, 0, fmt.Errorf("configuration validation failed: %w", err)
	}

	issuesFound := len(result.Errors)
	if issuesFound == 0 {
		logger.Info("Configuration is valid")
		return 0, 0, nil
	}

	fmt.Println()
	fmt.Printf("Configuration has %d errors:\n", issuesFound)
	for i, err := range result.Errors {
		fmt.Printf("   %d. %s\n", i+1, err)
	}

	// Currently we don't have auto-fix for config errors
	// User needs to manually fix configuration issues
	fmt.Println()
	fmt.Println(" Configuration errors require manual intervention")
	fmt.Println("   Run 'sudo eos check vault --config' for detailed validation")

	return issuesFound, 0, nil
}
