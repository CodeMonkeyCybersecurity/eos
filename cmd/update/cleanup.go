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

// Global flags
var (
	nonInteractive bool
	orphansOnly    bool
	kernelsOnly    bool
)

var cleanupCmd = &cobra.Command{
	Use:   "cleanup",
	Short: "Clean up unused packages and system files",
	Long: `Remove orphaned packages, unused dependencies, and old kernels.
	
This command performs comprehensive system cleanup by:
- Finding and removing orphaned packages (using deborphan)
- Running apt autoremove for unused dependencies  
- Identifying and optionally removing unused kernel packages

By default, runs in interactive mode for safety.`,
	RunE: eos_cli.Wrap(runSystemCleanup),
}

// runSystemCleanup executes system cleanup operations
func runSystemCleanup(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
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
		return runOrphansOnlyCleanup(cleanup, !nonInteractive)
	}

	if kernelsOnly {
		return runKernelsOnlyCleanup(cleanup, !nonInteractive)
	}

	// Full cleanup
	result, err := cleanup.PerformFullCleanup(!nonInteractive)
	if err != nil {
		return err
	}

	// Display results using the FormatResult method
	logger.Info(result.FormatResult())
	return nil
}

// runOrphansOnlyCleanup handles orphaned packages only
func runOrphansOnlyCleanup(cleanup *system.PackageCleanup, interactive bool) error {
	// Ensure deborphan is available
	if err := cleanup.EnsureDeborphan(); err != nil {
		return err
	}

	// Find orphaned packages
	orphans, err := cleanup.FindOrphanedPackages()
	if err != nil {
		return err
	}

	if len(orphans) == 0 {
		return nil
	}

	// Remove orphaned packages
	return cleanup.RemoveOrphanedPackages(orphans)
}

// runKernelsOnlyCleanup handles unused kernels only
func runKernelsOnlyCleanup(cleanup *system.PackageCleanup, interactive bool) error {
	// Find unused kernels
	kernels, err := cleanup.FindUnusedKernels()
	if err != nil {
		return err
	}

	if len(kernels) == 0 {
		return nil
	}

	// For safety, skip kernel removal in non-interactive mode
	if !interactive {
		return nil
	}

	// Remove unused kernels
	return cleanup.RemoveUnusedKernels(kernels)
}

func init() {
	UpdateCmd.AddCommand(cleanupCmd)

	cleanupCmd.Flags().BoolVarP(&nonInteractive, "yes", "y", false,
		"Run in non-interactive mode (skip prompts)")
	cleanupCmd.Flags().BoolVar(&orphansOnly, "orphans-only", false,
		"Only remove orphaned packages")
	cleanupCmd.Flags().BoolVar(&kernelsOnly, "kernels-only", false,
		"Only remove unused kernels")
}
