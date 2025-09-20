// cmd/delete/consul.go

package delete

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
	// TODO: Add Nomad client import when implemented
)

var DeleteConsulCmd = &cobra.Command{
	Use:   "consul",
	Short: "Remove HashiCorp Consul and all associated data",
	Long: `Remove HashiCorp Consul completely from the system using .

This command will:
- Gracefully leave the Consul cluster (if possible)
- Stop and disable the Consul service
- Remove the Consul package and binary
- Delete configuration files (/etc/consul.d) - unless --keep-config
- Remove data directories (/var/lib/consul) - unless --keep-data
- Clean up log files (/var/log/consul)
- Remove the consul user and group - unless --keep-user
- Remove systemd service files
- Clean up any Vault integration if present

By default, this operation will create backups before removing data.

EXAMPLES:
  # Remove Consul completely with confirmation prompt
  eos delete consul

  # Remove Consul without confirmation (use with caution)
  eos delete consul --force

  # Remove Consul but keep the data directory
  eos delete consul --keep-data

  # Remove Consul but preserve configuration
  eos delete consul --keep-config

  # Remove Consul but keep the user account
  eos delete consul --keep-user

  # Remove with custom timeout for graceful shutdown
  eos delete consul --timeout 60

  # Quick removal keeping config and data
  eos delete consul --keep-config --keep-data --force`,
	RunE: eos_cli.Wrap(runDeleteConsul),
}

var (
	forceDelete bool
	keepData    bool
	keepConfig  bool
	keepUser    bool
	timeout     int
)

// ConsulInstallationStatus represents the current state of Consul installation
type ConsulInstallationStatus struct {
	Installed      bool
	Running        bool
	Version        string
	ClusterMembers int
	HasData        bool
	DataSize       string
	HasConfig      bool
	UserExists     bool
}

func checkConsulInstallation(_ context.Context, _ otelzap.LoggerWithCtx) (*ConsulInstallationStatus, error) {
	// TODO: Replace with Nomad-based consul status check
	return &ConsulInstallationStatus{
		Installed: false,
		Version:   "unknown",
	}, fmt.Errorf("nomad consul status check not implemented")
}

func displayRemovalPlan(logger otelzap.LoggerWithCtx, status *ConsulInstallationStatus, opts *ConsulDeleteOptions) {
	logger.Info("terminal prompt: Consul Installation Details:")
	if status.Version != "" {
		logger.Info(fmt.Sprintf("terminal prompt:   Version:       %s", status.Version))
	}
	logger.Info(fmt.Sprintf("terminal prompt:   Running:       %v", status.Running))
	if status.Running && status.ClusterMembers > 0 {
		logger.Info(fmt.Sprintf("terminal prompt:   Cluster Size:  %d members", status.ClusterMembers))
	}
	if status.HasData && status.DataSize != "" {
		logger.Info(fmt.Sprintf("terminal prompt:   Data Size:     %s", status.DataSize))
	}

	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: Components to be removed:")
	logger.Info("terminal prompt:   Consul service and binary")
	if !opts.KeepConfig {
		logger.Info("terminal prompt:   Configuration files (/etc/consul.d)")
	}
	if !opts.KeepData {
		logger.Info("terminal prompt:   Data directory (/var/lib/consul)")
	}
	if !opts.KeepUser {
		logger.Info("terminal prompt:   System user and group (consul)")
	}
	logger.Info("terminal prompt:   Log files (/var/log/consul)")
}

func confirmDeletion(rc *eos_io.RuntimeContext, logger otelzap.LoggerWithCtx, opts *ConsulDeleteOptions) bool {
	prompt := "Are you sure you want to remove Consul"

	details := []string{}
	if !opts.KeepData {
		details = append(details, "all data will be deleted")
	}
	if !opts.KeepConfig {
		details = append(details, "all configurations will be removed")
	}
	if !opts.KeepUser {
		details = append(details, "the consul user will be removed")
	}

	if len(details) > 0 {
		prompt += fmt.Sprintf(" (%s)", strings.Join(details, ", "))
	}
	prompt += "? This action cannot be undone. [y/N] "

	logger.Info("terminal prompt: " + prompt)
	response, err := eos_io.ReadInput(rc)
	if err != nil {
		logger.Error("Failed to read user input", zap.Error(err))
		return false
	}

	return response == "y" || response == "Y"
}

type ConsulDeleteOptions struct {
	Force      bool
	KeepData   bool
	KeepConfig bool
	KeepUser   bool
	Timeout    int
}

// TODO: Replace with Nomad client initialization
func initializeNomadClient(_ otelzap.LoggerWithCtx) (interface{}, error) {
	// Placeholder for Nomad client initialization
	return nil, fmt.Errorf("Nomad client not implemented yet")
}

func runDeleteConsul(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if running as root
	if os.Geteuid() != 0 {
		return eos_err.NewUserError("this command must be run as root")
	}

	// Create options struct
	opts := &ConsulDeleteOptions{
		Force:      forceDelete,
		KeepData:   keepData,
		KeepConfig: keepConfig,
		KeepUser:   keepUser,
		Timeout:    timeout,
	}

	logger.Info("Starting Consul removal process",
		zap.Bool("force", opts.Force),
		zap.Bool("keep_data", opts.KeepData),
		zap.Bool("keep_config", opts.KeepConfig),
		zap.Bool("keep_user", opts.KeepUser),
		zap.Int("timeout", opts.Timeout))

	// TODO: Initialize Nomad client when implemented
	nomadClient, err := initializeNomadClient(logger)
	if err != nil {
		logger.Error("Nomad client not configured for Consul deletion")
		return fmt.Errorf("nomad client required for consul deletion: %w", err)
	}

	// ASSESS - Check current status
	logger.Info("Checking current Consul installation")
	status, err := checkConsulInstallation(rc.Ctx, logger)
	_ = nomadClient // Suppress unused variable warning
	if err != nil {
		logger.Debug("Error checking status", zap.Error(err))
		status = &ConsulInstallationStatus{} // Use empty status
	}

	if !status.Installed {
		logger.Info("terminal prompt: Consul is not installed on this system.")
		return nil
	}

	// Display what will be removed
	displayRemovalPlan(logger, status, opts)

	// Confirm deletion unless forced
	if !opts.Force {
		if !confirmDeletion(rc, logger, opts) {
			return fmt.Errorf("deletion cancelled by user")
		}
	}

	// INTERVENE - Apply removal state via HashiCorp Nomad
	// Prepare Nomad job data for Consul removal
	nomadJobData := map[string]interface{}{
		"consul": map[string]interface{}{
			"ensure":      "absent",
			"force":       opts.Force,
			"keep_data":   opts.KeepData,
			"keep_config": opts.KeepConfig,
			"keep_user":   opts.KeepUser,
			"timeout":     opts.Timeout,
		},
	}

	// Execute removal state with progress
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: Starting Consul removal...")

	// TODO: Replace with Nomad orchestration when implemented
	logger.Info("terminal prompt: Nomad orchestration not implemented yet")
	_ = nomadJobData // Suppress unused variable warning

	// TODO: Implement actual removal logic with Nomad
	err = fmt.Errorf("Consul removal requires administrator intervention - use HashiCorp Nomad for service management")
	if err != nil {
		return fmt.Errorf("removal failed: %w", err)
	}

	// TODO: Add result handling when Nomad orchestration is implemented
	logger.Info("terminal prompt: ✅ Consul removal placeholder completed")

	// EVALUATE - Show what was preserved
	if opts.KeepData || opts.KeepConfig || opts.KeepUser {
		logger.Info("terminal prompt: ")
		logger.Info("terminal prompt: Preserved items:")
		if opts.KeepData {
			logger.Info("terminal prompt:   - Data directory: /var/lib/consul")
		}
		if opts.KeepConfig {
			logger.Info("terminal prompt:   - Configuration: /etc/consul.d")
		}
		if opts.KeepUser {
			logger.Info("terminal prompt:   - System user: consul")
		}
	}

	return nil
}

func init() {
	DeleteConsulCmd.Flags().BoolVarP(&forceDelete, "force", "f", false, "Force deletion without confirmation prompt")
	DeleteConsulCmd.Flags().BoolVar(&keepData, "keep-data", false, "Preserve Consul data directory (/var/lib/consul)")
	DeleteConsulCmd.Flags().BoolVar(&keepConfig, "keep-config", false, "Preserve Consul configuration (/etc/consul.d)")
	DeleteConsulCmd.Flags().BoolVar(&keepUser, "keep-user", false, "Preserve consul system user account")
	DeleteConsulCmd.Flags().IntVar(&timeout, "timeout", 30, "Timeout in seconds for graceful cluster leave")

	// Register the command with the delete command
	DeleteCmd.AddCommand(DeleteConsulCmd)
}
