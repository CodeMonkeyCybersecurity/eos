// cmd/delete/boundary.go

package delete

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/boundary"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var DeleteBoundaryCmd = &cobra.Command{
	Use:   "boundary",
	Short: "Remove HashiCorp Boundary and all associated data",
	Long: `Remove HashiCorp Boundary completely from the system using .

This command will:
- Stop and disable the Boundary service
- Remove the Boundary package and binary
- Delete configuration files (/etc/boundary) - unless --keep-config
- Remove data directories (/var/lib/boundary) - unless --keep-data
- Clean up log files (/var/log/boundary)
- Remove the boundary user and group - unless --keep-user
- Remove systemd service files
- Clean up any database tables (for controllers)

By default, this operation will prompt for confirmation before removing data.

EXAMPLES:
  # Remove Boundary completely with confirmation prompt
  eos delete boundary

  # Remove Boundary without confirmation (use with caution)
  eos delete boundary --force

  # Remove Boundary but keep the data directory
  eos delete boundary --keep-data

  # Remove Boundary but preserve configuration
  eos delete boundary --keep-config

  # Remove Boundary but keep the user account
  eos delete boundary --keep-user

  # Quick removal keeping config and data
  eos delete boundary --keep-config --keep-data --force`,
	RunE: eos.Wrap(runDeleteBoundary),
}

var (
	deleteBoundaryForce      bool
	deleteBoundaryKeepData   bool
	deleteBoundaryKeepConfig bool
	deleteBoundaryKeepUser   bool
	deleteBoundaryCluster    string
	deleteBoundaryStream     bool
)

func runDeleteBoundary(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if running as root
	if os.Geteuid() != 0 {
		return eos_err.NewUserError("this command must be run as root")
	}

	logger.Info("Starting Boundary removal process",
		zap.Bool("force", deleteBoundaryForce),
		zap.Bool("keep_data", deleteBoundaryKeepData),
		zap.Bool("keep_config", deleteBoundaryKeepConfig),
		zap.Bool("keep_user", deleteBoundaryKeepUser),
		zap.String("cluster", deleteBoundaryCluster))

	// TODO: Replace with Nomad connectivity check
	logger.Info("Using Nomad orchestration for Boundary deletion")

	// Create Boundary manager
	manager, err := boundary.NewManager(rc)
	if err != nil {
		return fmt.Errorf("failed to create boundary manager: %w", err)
	}

	// Check current status
	logger.Info("Checking current Boundary status")
	statusOpts := &boundary.StatusOptions{
		Target:      "*",
		ClusterName: deleteBoundaryCluster,
		Detailed:    true,
	}
	err = manager.Status(rc.Ctx, statusOpts)
	if err != nil {
		logger.Warn("Failed to check Boundary status, proceeding with deletion", zap.Error(err))
	}

	// Check if anything needs to be removed - HashiCorp Boundary via Nomad
	logger.Info("Checking for HashiCorp Boundary installations via Nomad")
	runningInstances := []string{}
	failedInstances := []string{}

	// Display current status
	displayBoundaryRemovalStatus(logger, nil, runningInstances, failedInstances)

	// Confirmation prompt
	if !deleteBoundaryForce {
		prompt := "Are you sure you want to remove Boundary"
		details := []string{}

		if !deleteBoundaryKeepData {
			details = append(details, "all data will be deleted")
		}
		if !deleteBoundaryKeepConfig {
			details = append(details, "all configurations will be removed")
		}
		if !deleteBoundaryKeepUser {
			details = append(details, "the boundary user will be removed")
		}

		if len(details) > 0 {
			prompt += " (" + strings.Join(details, ", ") + ")"
		}
		prompt += "? This action cannot be undone. [y/N]"

		logger.Info("terminal prompt: " + prompt)
		response, err := eos_io.ReadInput(rc)
		if err != nil {
			return fmt.Errorf("failed to read user input: %w", err)
		}

		if response != "y" && response != "Y" {
			logger.Info("Boundary deletion cancelled by user")
			return nil
		}
	}

	// Create delete options
	deleteOpts := &boundary.DeleteOptions{
		Target:       "*",
		ClusterName:  deleteBoundaryCluster,
		KeepData:     deleteBoundaryKeepData,
		KeepConfig:   deleteBoundaryKeepConfig,
		KeepUser:     deleteBoundaryKeepUser,
		Force:        deleteBoundaryForce,
		StreamOutput: deleteBoundaryStream,
		Timeout:      30 * time.Minute,
	}

	// Execute removal
	logger.Info("terminal prompt: Starting Boundary removal...")

	if deleteBoundaryStream {
		logger.Info("terminal prompt: Streaming removal progress...")
	}

	err = manager.Delete(rc.Ctx, deleteOpts)
	if err != nil {
		return fmt.Errorf("boundary removal failed: %w", err)
	}

	// Verify removal
	logger.Info("Verifying Boundary removal")
	time.Sleep(2 * time.Second)

	err = manager.Status(rc.Ctx, statusOpts)
	if err != nil {
		logger.Warn("Could not verify final status", zap.Error(err))
	} else {
		logger.Info("Final status check completed - Nomad implementation pending")
		// TODO: Implement proper status verification with Nomad
	}

	logger.Info("terminal prompt:  Boundary removal completed successfully!")

	// Show what was preserved
	if deleteBoundaryKeepData || deleteBoundaryKeepConfig || deleteBoundaryKeepUser {
		logger.Info("terminal prompt: ")
		logger.Info("terminal prompt: Preserved components:")
		if deleteBoundaryKeepData {
			logger.Info("terminal prompt:   - Data directory: /var/lib/boundary")
		}
		if deleteBoundaryKeepConfig {
			logger.Info("terminal prompt:   - Configuration: /etc/boundary")
		}
		if deleteBoundaryKeepUser {
			logger.Info("terminal prompt:   - System user: boundary")
		}
		logger.Info("terminal prompt: ")
		logger.Info("terminal prompt: To completely remove these later, run:")
		logger.Info("terminal prompt:   eos delete boundary --force")
	}

	return nil
}

func displayBoundaryRemovalStatus(logger otelzap.LoggerWithCtx, _ interface{}, running, _ []string) {
	logger.Info("terminal prompt: Current HashiCorp Boundary Installation Status:")
	logger.Info(fmt.Sprintf("terminal prompt:   Running instances: %d", len(running)))

	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: Components to be removed:")
	logger.Info("terminal prompt:   ✓ Boundary service and binary")
	if !deleteBoundaryKeepConfig {
		logger.Info("terminal prompt:   ✓ Configuration files (/etc/boundary)")
	}
	if !deleteBoundaryKeepData {
		logger.Info("terminal prompt:   ✓ Data directory (/var/lib/boundary)")
	}
	if !deleteBoundaryKeepUser {
		logger.Info("terminal prompt:   ✓ System user and group (boundary)")
	}
	logger.Info("terminal prompt:   ✓ Log files (/var/log/boundary)")
	logger.Info("terminal prompt:   ✓ Systemd service files")
}

func init() {
	DeleteBoundaryCmd.Flags().BoolVarP(&deleteBoundaryForce, "force", "f", false, "Force deletion without confirmation prompt")
	DeleteBoundaryCmd.Flags().BoolVar(&deleteBoundaryKeepData, "keep-data", false, "Preserve Boundary data directory (/var/lib/boundary)")
	DeleteBoundaryCmd.Flags().BoolVar(&deleteBoundaryKeepConfig, "keep-config", false, "Preserve Boundary configuration (/etc/boundary)")
	DeleteBoundaryCmd.Flags().BoolVar(&deleteBoundaryKeepUser, "keep-user", false, "Preserve boundary system user account")
	DeleteBoundaryCmd.Flags().StringVar(&deleteBoundaryCluster, "cluster", "eos", "Boundary cluster name")
	DeleteBoundaryCmd.Flags().BoolVar(&deleteBoundaryStream, "stream", false, "Stream removal output in real-time")

	// Register the command with the delete command
	DeleteCmd.AddCommand(DeleteBoundaryCmd)
}
