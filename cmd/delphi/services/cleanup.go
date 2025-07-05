// cmd/delphi/services/cleanup.go

package services

import (
	"fmt"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// NewCleanupCmd creates the cleanup command
func NewCleanupCmd() *cobra.Command {
	var (
		dryRun  bool
		autoFix bool
	)

	cmd := &cobra.Command{
		Use:   "cleanup",
		Short: "Detect and fix zombie services (running without unit files)",
		Long: `Detect and safely remove zombie services that are running but have no systemd unit file.

This command helps fix the dangerous situation where services are running but their 
unit files have been removed, causing systemd to loop endlessly trying to manage them.

The cleanup process follows systemd best practices:
1. Stop running processes (graceful SIGTERM, then SIGKILL if needed)
2. Disable services (if unit file exists)
3. Remove unit files
4. Reload systemd daemon

Examples:
  eos delphi services cleanup --dry-run      # Show what would be cleaned up
  eos delphi services cleanup --auto-fix     # Automatically fix zombie services
  eos delphi services cleanup                # Interactive cleanup`,
		RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
			logger := otelzap.Ctx(rc.Ctx)

			logger.Info("🧹 Starting Delphi service cleanup",
				zap.Bool("dry_run", dryRun),
				zap.Bool("auto_fix", autoFix))

			lifecycleManager := shared.GetGlobalServiceLifecycleManager()

			// Detect zombie services
			zombieServices, err := lifecycleManager.DetectZombieServices(rc.Ctx)
			if err != nil {
				return fmt.Errorf("failed to detect zombie services: %w", err)
			}

			if len(zombieServices) == 0 {
				logger.Info(" No zombie services detected - system is clean")
				return nil
			}

			// Report findings
			logger.Error(" Zombie services detected",
				zap.Int("zombie_count", len(zombieServices)))

			for _, zombie := range zombieServices {
				logger.Error(" Zombie service details",
					zap.String("service", zombie.ServiceName),
					zap.Bool("is_running", zombie.IsRunning),
					zap.Bool("has_unit_file", zombie.HasUnitFile),
					zap.Int("pid", zombie.PID),
					zap.String("problem", "Running process without systemd unit file"))
			}

			if dryRun {
				logger.Info(" DRY RUN - Would perform the following cleanup actions:")
				for _, zombie := range zombieServices {
					logger.Info(" Cleanup plan for zombie service",
						zap.String("service", zombie.ServiceName),
						zap.Bool("would_stop", zombie.RequiresStop),
						zap.Bool("would_disable", zombie.RequiresDisable),
						zap.Bool("would_remove_unit", zombie.RequiresRemoval))
				}
				logger.Info(" To actually fix these issues, run: eos delphi services cleanup --auto-fix")
				return nil
			}

			if !autoFix {
				logger.Error(" Zombie services require manual intervention")
				logger.Info(" Options to fix:")
				logger.Info("  1. Run with --auto-fix to automatically clean up zombie services")
				logger.Info("  2. Run with --dry-run first to see what would be done")
				logger.Info("  3. Manually stop processes and clean up unit files")
				return fmt.Errorf("zombie services detected - manual intervention required")
			}

			// Auto-fix zombie services
			logger.Info(" Auto-fixing zombie services")

			for i, zombie := range zombieServices {
				logger.Info(" Cleaning up zombie service",
					zap.String("service", zombie.ServiceName),
					zap.Int("progress", i+1),
					zap.Int("total", len(zombieServices)))

				if err := lifecycleManager.SafelyRemoveService(rc.Ctx, zombie.ServiceName); err != nil {
					logger.Error(" Failed to clean up zombie service",
						zap.String("service", zombie.ServiceName),
						zap.Error(err))
					return fmt.Errorf("failed to clean up zombie service %s: %w", zombie.ServiceName, err)
				}

				logger.Info(" Zombie service cleaned up successfully",
					zap.String("service", zombie.ServiceName))
			}

			logger.Info(" Zombie service cleanup completed",
				zap.Int("services_cleaned", len(zombieServices)))

			// Verify cleanup was successful
			logger.Info(" Verifying cleanup was successful")
			remainingZombies, err := lifecycleManager.DetectZombieServices(rc.Ctx)
			if err != nil {
				logger.Warn("Failed to verify cleanup", zap.Error(err))
			} else if len(remainingZombies) > 0 {
				logger.Error("  Some zombie services still remain",
					zap.Int("remaining_zombies", len(remainingZombies)))
			} else {
				logger.Info(" Cleanup verification successful - no zombie services remain")
			}

			return nil
		}),
	}

	cmd.Flags().BoolVarP(&dryRun, "dry-run", "n", false, "Show what would be cleaned up without making changes")
	cmd.Flags().BoolVar(&autoFix, "auto-fix", false, "Automatically fix zombie services without prompting")

	return cmd
}
