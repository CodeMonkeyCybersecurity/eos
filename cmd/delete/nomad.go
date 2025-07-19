// cmd/delete/nomad.go
package delete

import (
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/nomad"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var DeleteNomadCmd = &cobra.Command{
	Use:          "nomad",
	SilenceUsage: true,
	Short:        "Uninstall Nomad from this machine",
	Long: `Safely removes HashiCorp Nomad from the system.
This command stops Nomad services, drains running jobs if possible, 
and removes Nomad binaries and configuration files.

Uninstallation process:
1. Stop Nomad services gracefully
2. Drain running jobs (if server)
3. Remove Nomad binaries and configuration
4. Clean up data directories
5. Verify complete removal

Use this after migrating workloads away from Nomad or when decommissioning nodes.

Examples:
  eos delete nomad                    # Standard uninstallation
  eos delete nomad --force           # Force removal without draining
  eos delete nomad --preserve-data   # Keep data directories`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)
		
		force, _ := cmd.Flags().GetBool("force")
		preserveData, _ := cmd.Flags().GetBool("preserve-data")
		
		logger.Info("Starting Nomad uninstallation",
			zap.Bool("force", force),
			zap.Bool("preserve_data", preserveData))
		
		// Create migration manager for uninstallation
		migrationManager := nomad.NewMigrationManager(logger)
		
		// Uninstall Nomad
		if err := migrationManager.UninstallNomad(rc, force, preserveData); err != nil {
			logger.Error("Nomad uninstallation failed", zap.Error(err))
			return err
		}
		
		logger.Info("Nomad uninstallation completed successfully")
		logger.Info("terminal prompt: ✅ Nomad Uninstallation Complete!")
		logger.Info("terminal prompt: ")
		logger.Info("terminal prompt: Removal Summary:")
		logger.Info("terminal prompt:   - Nomad services: Stopped and removed")
		logger.Info("terminal prompt:   - Nomad binaries: Removed")
		logger.Info("terminal prompt:   - Configuration files: Removed")
		if !preserveData {
			logger.Info("terminal prompt:   - Data directories: Cleaned")
		} else {
			logger.Info("terminal prompt:   - Data directories: Preserved")
		}
		logger.Info("terminal prompt: ")
		logger.Info("terminal prompt: System is now ready for alternative orchestration or cleanup.")
		
		return nil
	}),
}

func init() {
	DeleteCmd.AddCommand(DeleteNomadCmd)
	
	// Add flags for uninstallation options
	DeleteNomadCmd.Flags().Bool("force", false, "Force removal without graceful draining")
	DeleteNomadCmd.Flags().Bool("preserve-data", false, "Preserve data directories during removal")
}