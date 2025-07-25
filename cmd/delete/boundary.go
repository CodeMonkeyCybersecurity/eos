// cmd/delete/boundary.go

package delete

import (
	"fmt"
	"os"
	"strings"
	"time"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/boundary"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/salt"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var DeleteBoundaryCmd = &cobra.Command{
	Use:   "boundary",
	Short: "Remove HashiCorp Boundary and all associated data",
	Long: `Remove HashiCorp Boundary completely from the system using SaltStack.

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
	
	// Initialize Salt client
	saltClient, err := initializeDeleteBoundarySaltClient(logger)
	if err != nil {
		logger.Info("Salt API not configured, falling back to local salt-call execution")
		return runDeleteBoundaryFallback(rc, cmd, args)
	}
	
	// Create Boundary manager
	manager, err := boundary.NewManager(rc, saltClient)
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
	
	status, err := manager.Status(rc.Ctx, statusOpts)
	if err != nil {
		logger.Warn("Failed to check Boundary status", zap.Error(err))
		status = &boundary.StatusResult{
			Minions: make(map[string]boundary.MinionStatus),
		}
	}
	
	// Check if anything needs to be removed
	hasInstallation := false
	runningInstances := []string{}
	failedInstances := []string{}
	
	for minion, minionStatus := range status.Minions {
		if minionStatus.Status.Installed {
			hasInstallation = true
			if minionStatus.Status.Running {
				runningInstances = append(runningInstances, minion)
			}
			if minionStatus.Status.Failed {
				failedInstances = append(failedInstances, minion)
			}
		}
	}
	
	if !hasInstallation {
		logger.Info("terminal prompt: Boundary is not installed on any target minions - nothing to remove")
		return nil
	}
	
	// Display current status
	displayBoundaryRemovalStatus(logger, status, runningInstances, failedInstances)
	
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
	
	finalStatus, err := manager.Status(rc.Ctx, statusOpts)
	if err != nil {
		logger.Warn("Could not verify final status", zap.Error(err))
	} else {
		remainingInstances := []string{}
		for minion, minionStatus := range finalStatus.Minions {
			if minionStatus.Status.Installed {
				remainingInstances = append(remainingInstances, minion)
			}
		}
		
		if len(remainingInstances) > 0 {
			logger.Warn("Some Boundary instances may still be present",
				zap.Strings("minions", remainingInstances))
		}
	}
	
	logger.Info("terminal prompt: ✅ Boundary removal completed successfully!")
	
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

func initializeDeleteBoundarySaltClient(logger otelzap.LoggerWithCtx) (*salt.Client, error) {
	// Get underlying zap logger
	baseLogger := logger.ZapLogger()
	config := salt.ClientConfig{
		BaseURL:            getEnvOrDefault("SALT_API_URL", "https://localhost:8000"),
		Username:           getEnvOrDefault("SALT_API_USER", "eos-service"),
		Password:           os.Getenv("SALT_API_PASSWORD"),
		EAuth:              "pam",
		Timeout:            10 * time.Minute,
		MaxRetries:         3,
		InsecureSkipVerify: getEnvOrDefault("SALT_API_INSECURE", "false") == "true",
		Logger:             baseLogger,
	}
	
	if config.Password == "" {
		// Fall back to using salt-call directly if API is not configured
		return nil, fmt.Errorf("Salt API not configured")
	}
	
	return salt.NewClient(config)
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func displayBoundaryRemovalStatus(logger otelzap.LoggerWithCtx, status *boundary.StatusResult, running, failed []string) {
	logger.Info("terminal prompt: Current Boundary Installation Status:")
	logger.Info(fmt.Sprintf("terminal prompt:   Total installations: %d", len(status.Minions)))
	
	if len(running) > 0 {
		logger.Info(fmt.Sprintf("terminal prompt:   Running instances: %d", len(running)))
		for _, minion := range running {
			s := status.Minions[minion].Status
			logger.Info(fmt.Sprintf("terminal prompt:     - %s (%s, version %s)", minion, s.Role, s.Version))
		}
	}
	
	if len(failed) > 0 {
		logger.Info(fmt.Sprintf("terminal prompt:   Failed instances: %d", len(failed)))
		for _, minion := range failed {
			logger.Info(fmt.Sprintf("terminal prompt:     - %s", minion))
		}
	}
	
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

// runDeleteBoundaryFallback is the fallback implementation using salt-call
func runDeleteBoundaryFallback(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	// This would contain the original shell-based implementation
	// For now, we'll return an error indicating API is required
	return fmt.Errorf("Salt API required for Boundary removal. Please configure SALT_API_* environment variables")
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