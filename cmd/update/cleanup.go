// cmd/update/cleanup.go
package update

import (
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/system"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)
var cleanupCmd = &cobra.Command{
	Use:   "cleanup",
	Short: "Clean up unused packages and system files",
	Long: `Remove orphaned packages, unused dependencies, and old kernels.
	
This command performs comprehensive system cleanup by:
- Finding and removing orphaned packages (using deborphan)
- Running apt autoremove for unused dependencies  
- Identifying and optionally removing unused kernel packages

By default, runs in interactive mode for safety. Use --yes to run non-interactively.

Examples:
  eos update cleanup                    # Interactive cleanup of all components
  eos update cleanup --yes              # Non-interactive cleanup
  eos update cleanup --orphans-only     # Only remove orphaned packages
  eos update cleanup --kernels-only     # Only remove unused kernels
  eos update cleanup --yes --orphans-only  # Non-interactive orphan cleanup`,
	RunE: eos_cli.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)
		// Get flags
		nonInteractive, _ := cmd.Flags().GetBool("yes")
		orphansOnly, _ := cmd.Flags().GetBool("orphans-only")
		kernelsOnly, _ := cmd.Flags().GetBool("kernels-only")
		
		logger.Info("Starting system cleanup",
			zap.Bool("non_interactive", nonInteractive),
			zap.Bool("orphans_only", orphansOnly),
			zap.Bool("kernels_only", kernelsOnly))

		// Create cleanup instance
		cleanup := system.NewPackageCleanup(rc)

		// Check root privileges
		if err := cleanup.CheckRoot(); err != nil {
			return err
		}

		// Execute cleanup based on flags
		if orphansOnly {
			return system.RunOrphansOnlyCleanup(rc, cleanup, !nonInteractive)
		}

		if kernelsOnly {
			return system.RunKernelsOnlyCleanup(rc, cleanup, !nonInteractive)
		}

		// Full cleanup
		result, err := cleanup.PerformFullCleanup(!nonInteractive)
		if err != nil {
			return err
		}

		// Display results using the FormatResult method
		logger.Info(result.FormatResult())
		return nil
	}),
}

// All helper functions have been moved to pkg/system/

func init() {
	UpdateCmd.AddCommand(cleanupCmd)

	cleanupCmd.Flags().BoolP("yes", "y", false,
		"Run in non-interactive mode (skip prompts)")
	cleanupCmd.Flags().Bool("orphans-only", false,
		"Only remove orphaned packages")
	cleanupCmd.Flags().Bool("kernels-only", false,
		"Only remove unused kernels")
}
