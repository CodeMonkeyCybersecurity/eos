// cmd/system/cleanup.go
package system

import (
	"fmt"

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

By default, runs in interactive mode for safety.`,
	RunE: eos_cli.Wrap(runSystemCleanup),
}

var (
	nonInteractive bool
	orphansOnly    bool
	kernelsOnly    bool
)

func init() {
	SystemCmd.AddCommand(cleanupCmd)

	cleanupCmd.Flags().BoolVarP(&nonInteractive, "yes", "y", false,
		"Run in non-interactive mode (skip prompts)")
	cleanupCmd.Flags().BoolVar(&orphansOnly, "orphans-only", false,
		"Only remove orphaned packages")
	cleanupCmd.Flags().BoolVar(&kernelsOnly, "kernels-only", false,
		"Only remove unused kernels")
}

func runSystemCleanup(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting system cleanup")

	cleanup := system.NewPackageCleanup(rc)

	// Check root privileges
	if err := cleanup.CheckRoot(); err != nil {
		return err
	}

	interactive := !nonInteractive

	logger.Info("System cleanup configuration",
		zap.Bool("interactive", interactive),
		zap.Bool("orphans_only", orphansOnly),
		zap.Bool("kernels_only", kernelsOnly))

	if orphansOnly {
		return runOrphansCleanup(cleanup, interactive)
	}

	if kernelsOnly {
		return runKernelsCleanup(cleanup, interactive)
	}

	// Run full cleanup
	result, err := cleanup.PerformFullCleanup(interactive)
	if err != nil {
		return fmt.Errorf("system cleanup failed: %w", err)
	}

	// Display results
	fmt.Print(result.FormatResult())

	logger.Info("System cleanup completed successfully",
		zap.Int("orphaned_packages", len(result.OrphanedPackages)),
		zap.Bool("orphans_removed", result.OrphansRemoved),
		zap.Bool("autoremove_ran", result.AutoremoveRan),
		zap.Int("unused_kernels", len(result.UnusedKernels)),
		zap.Bool("kernels_removed", result.KernelsRemoved))

	return nil
}

// runOrphansCleanup handles orphaned packages only
func runOrphansCleanup(cleanup *system.PackageCleanup, interactive bool) error {
	fmt.Println("🔍 Finding orphaned packages...")

	// Ensure deborphan is available
	if err := cleanup.EnsureDeborphan(); err != nil {
		return fmt.Errorf("failed to ensure deborphan: %w", err)
	}

	// Find orphaned packages
	orphans, err := cleanup.FindOrphanedPackages()
	if err != nil {
		return fmt.Errorf("failed to find orphaned packages: %w", err)
	}

	if len(orphans) == 0 {
		fmt.Println("✅ No orphaned packages found")
		return nil
	}

	fmt.Printf("📦 Found %d orphaned packages:\n", len(orphans))
	for _, pkg := range orphans {
		fmt.Printf("  - %s\n", pkg)
	}

	// Remove orphaned packages
	shouldRemove := true
	if interactive {
		fmt.Printf("\nRemove these %d orphaned packages? (y/n): ", len(orphans))
		var response string
		fmt.Scanln(&response)
		shouldRemove = response == "y" || response == "Y" || response == "yes"
	}

	if shouldRemove {
		if err := cleanup.RemoveOrphanedPackages(orphans); err != nil {
			return fmt.Errorf("failed to remove orphaned packages: %w", err)
		}
		fmt.Println("✅ Orphaned packages removed successfully")
	} else {
		fmt.Println("⏭️  Skipped removal of orphaned packages")
	}

	return nil
}

// runKernelsCleanup handles unused kernels only
func runKernelsCleanup(cleanup *system.PackageCleanup, interactive bool) error {
	fmt.Println("🔍 Finding unused kernels...")

	// Find unused kernels
	kernels, err := cleanup.FindUnusedKernels()
	if err != nil {
		return fmt.Errorf("failed to find unused kernels: %w", err)
	}

	if len(kernels) == 0 {
		fmt.Println("✅ No unused kernels found")
		return nil
	}

	fmt.Printf("🐧 Found %d unused kernels:\n", len(kernels))
	for _, kernel := range kernels {
		fmt.Printf("  - %s\n", kernel)
	}

	// Remove unused kernels
	shouldRemove := false
	if interactive {
		fmt.Printf("\nRemove these %d unused kernels? (y/n): ", len(kernels))
		var response string
		fmt.Scanln(&response)
		shouldRemove = response == "y" || response == "Y" || response == "yes"
	}

	if shouldRemove {
		if err := cleanup.RemoveUnusedKernels(kernels); err != nil {
			return fmt.Errorf("failed to remove unused kernels: %w", err)
		}
		fmt.Println("✅ Unused kernels removed successfully")
	} else {
		fmt.Println("⏭️  Skipped removal of unused kernels")
	}

	return nil
}