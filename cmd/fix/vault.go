// cmd/fix/vault.go

package fix

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	vaultfix "github.com/CodeMonkeyCybersecurity/eos/pkg/vault/fix"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var vaultFixCmd = &cobra.Command{
	Use:   "vault",
	Short: "[DEPRECATED] Fix common Vault installation issues - use 'eos update vault --fix'",
	Long: `  DEPRECATION WARNING:
This command is deprecated and will be removed in Eos v2.0.0 (approximately 6 months from now).

Use 'eos update vault --fix' instead for configuration drift correction.

Migration guide:
  eos fix vault --all           →  eos update vault --fix
  eos fix vault --all --dry-run →  eos update vault --drift

The new 'eos update vault --fix' provides the same functionality with better
semantics: it compares current state against canonical state and corrects drift.

Legacy functionality (still works):
- Duplicate binary installations
- File permissions on config/data/TLS files
- Systemd service configuration
- Configuration file syntax
- Missing directories
- Incorrect API and cluster addresses (localhost → hostname)

EXAMPLES (DEPRECATED - use 'eos update vault --fix' instead):
  # Auto-repair all detected issues
  sudo eos fix vault --all

  # Dry-run to see what would be fixed (no changes made)
  sudo eos fix vault --all --dry-run

  # Only cleanup duplicate binaries
  sudo eos fix vault --cleanup-binaries

  # Only fix file permissions
  sudo eos fix vault --permissions

  # Only repair configuration
  sudo eos fix vault --config

  # Only fix API/cluster addresses
  sudo eos fix vault --addresses`,

	RunE: eos_cli.Wrap(runVaultFix),
}

func init() {
	vaultFixCmd.Flags().Bool("dry-run", false, "Show what would be fixed without making changes")
	vaultFixCmd.Flags().Bool("cleanup-binaries", false, "Remove duplicate vault binaries")
	vaultFixCmd.Flags().Bool("permissions", false, "Fix file permissions and ownership")
	vaultFixCmd.Flags().Bool("config", false, "Repair configuration files")
	vaultFixCmd.Flags().Bool("addresses", false, "Fix incorrect API and cluster addresses")
	vaultFixCmd.Flags().Bool("all", false, "Repair all detected issues")
}

func runVaultFix(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Print deprecation warning
	logger.Warn("  DEPRECATION WARNING: 'eos fix vault' is deprecated")
	logger.Warn("   Use 'eos update vault --fix' instead")
	logger.Warn("   This command will be removed in Eos v2.0.0 (approximately 6 months from now)")
	logger.Info("")

	logger.Info("Starting Vault repair")

	// Parse flags into config
	dryRun, _ := cmd.Flags().GetBool("dry-run")
	cleanupBinaries, _ := cmd.Flags().GetBool("cleanup-binaries")
	permissions, _ := cmd.Flags().GetBool("permissions")
	repairConfig, _ := cmd.Flags().GetBool("config")
	fixAddresses, _ := cmd.Flags().GetBool("addresses")
	all, _ := cmd.Flags().GetBool("all")

	config := &vaultfix.Config{
		DryRun:          dryRun,
		CleanupBinaries: cleanupBinaries,
		FixPermissions:  permissions,
		RepairConfig:    repairConfig,
		FixAddresses:    fixAddresses,
		All:             all,
	}

	if dryRun {
		logger.Info("DRY-RUN MODE: No changes will be made")
		fmt.Println("DRY-RUN MODE: Analyzing issues without making changes")
	}

	// Delegate to pkg/vault/fix - ALL business logic lives there
	result, err := vaultfix.RunFixes(rc, config)
	if err != nil {
		return err
	}

	// Display summary (simple orchestration)
	displaySummary(rc, result, dryRun)

	return nil
}

// displaySummary shows the repair results
func displaySummary(rc *eos_io.RuntimeContext, result *vaultfix.RepairResult, dryRun bool) {
	logger := otelzap.Ctx(rc.Ctx)

	fmt.Println()
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println("Repair Summary")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Printf("Issues found: %d\n", result.IssuesFound)

	if dryRun {
		fmt.Printf("Would fix: %d (DRY-RUN - no changes made)\n", result.IssuesFixed)
		fmt.Println("\nRun without --dry-run to apply fixes")
	} else {
		fmt.Printf("Issues fixed: %d\n", result.IssuesFixed)
	}

	if result.IssuesFound == 0 {
		fmt.Println("\nNo issues detected - Vault installation is healthy")
	} else if !dryRun && result.IssuesFixed == result.IssuesFound {
		fmt.Println("\nAll issues successfully repaired")
	} else if !dryRun && result.IssuesFixed < result.IssuesFound {
		fmt.Printf("\n%d issues could not be automatically repaired\n", result.IssuesFound-result.IssuesFixed)
		fmt.Println("Run 'sudo eos debug vault' for detailed diagnostics")
	}

	if len(result.Errors) > 0 {
		fmt.Printf("\nEncountered %d errors during repair:\n", len(result.Errors))
		for i, err := range result.Errors {
			fmt.Printf("  %d. %v\n", i+1, err)
		}
	}

	logger.Info("Vault repair completed",
		zap.Int("issues_found", result.IssuesFound),
		zap.Int("issues_fixed", result.IssuesFixed),
		zap.Bool("dry_run", dryRun))
}
