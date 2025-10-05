// cmd/delete/nomad.go

package delete

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/nomad"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var DeleteNomadCmd = &cobra.Command{
	Use:   "nomad",
	Short: "Remove HashiCorp Nomad and all associated data",
	Long: `Remove HashiCorp Nomad completely from the system using .

This command will:
- Gracefully drain node if running as client
- Stop all running jobs (if server)
- Leave the Nomad cluster gracefully
- Stop and disable the Nomad service
- Remove the Nomad package and binary
- Delete configuration files (/etc/nomad.d) - unless --keep-config
- Remove data directories (/var/lib/nomad) - unless --keep-data
- Clean up log files (/var/log/nomad)
- Remove the nomad user and group - unless --keep-user
- Remove systemd service files

By default, this operation will create backups before removing data.

EXAMPLES:
  # Remove Nomad completely with confirmation prompt
  eos delete nomad

  # Remove Nomad without confirmation (use with caution)
  eos delete nomad --force

  # Remove Nomad but keep the data directory
  eos delete nomad --keep-data

  # Remove Nomad but preserve configuration
  eos delete nomad --keep-config

  # Remove Nomad but keep the user account
  eos delete nomad --keep-user

  # Remove with custom timeout for graceful shutdown
  eos delete nomad --timeout 60

  # Quick removal keeping config and data
  eos delete nomad --keep-config --keep-data --force`,
	RunE: eos.Wrap(runDeleteNomad),
}

var (
	nomadForceDelete bool
	nomadKeepData    bool
	nomadKeepConfig  bool
	nomadKeepUser    bool
	nomadTimeout     int
)

// NomadStatus represents the current state of Nomad installation
type NomadDeleteStatus struct {
	Installed      bool
	Running        bool
	Failed         bool
	ConfigValid    bool
	Version        string
	ServiceStatus  string
	ServerMode     bool
	ClientMode     bool
	NodeID         string
	ClusterMembers []string
	RunningJobs    []string
	HasData        bool
	HasConfig      bool
	UserExists     bool
}

func checkNomadDeleteStatus(rc *eos_io.RuntimeContext) (*NomadDeleteStatus, error) {
	logger := otelzap.Ctx(rc.Ctx)
	status := &NomadDeleteStatus{}

	// Check if Nomad binary exists
	if nomadPath, err := exec.LookPath("nomad"); err == nil {
		status.Installed = true
		logger.Debug("Nomad binary found", zap.String("path", nomadPath))

		// Get version
		if output, err := exec.Command("nomad", "version").Output(); err == nil {
			lines := strings.Split(string(output), "\n")
			if len(lines) > 0 {
				status.Version = strings.TrimSpace(lines[0])
			}
		}
	}

	// Check service status
	if output, err := exec.Command("systemctl", "is-active", "nomad").Output(); err == nil {
		status.ServiceStatus = strings.TrimSpace(string(output))
		status.Running = (status.ServiceStatus == "active")
	} else {
		// Check if service is in failed state
		if exec.Command("systemctl", "is-failed", "nomad").Run() == nil {
			status.Failed = true
			status.ServiceStatus = "failed"
		}
	}

	// Check server/client mode and cluster status if running
	if status.Running {
		// Check agent info
		if output, err := exec.Command("nomad", "agent-info").Output(); err == nil {
			outputStr := string(output)
			status.ServerMode = strings.Contains(outputStr, "server = true")
			status.ClientMode = strings.Contains(outputStr, "client = true")

			// Extract node ID
			lines := strings.Split(outputStr, "\n")
			for _, line := range lines {
				if strings.Contains(line, "node_id") {
					parts := strings.Split(line, "=")
					if len(parts) > 1 {
						status.NodeID = strings.TrimSpace(parts[1])
					}
				}
			}
		}

		// Get server members (for server mode)
		if status.ServerMode {
			if output, err := exec.Command("nomad", "server", "members").Output(); err == nil {
				lines := strings.Split(string(output), "\n")
				for _, line := range lines {
					line = strings.TrimSpace(line)
					if line != "" && !strings.HasPrefix(line, "Name") {
						status.ClusterMembers = append(status.ClusterMembers, line)
					}
				}
			}
		}

		// Get running jobs
		if output, err := exec.Command("nomad", "job", "status", "-short").Output(); err == nil {
			lines := strings.Split(string(output), "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if line != "" && !strings.HasPrefix(line, "ID") {
					parts := strings.Fields(line)
					if len(parts) > 0 {
						status.RunningJobs = append(status.RunningJobs, parts[0])
					}
				}
			}
		}
	}

	// Check for data directory
	if info, err := os.Stat("/var/lib/nomad"); err == nil && info.IsDir() {
		entries, _ := os.ReadDir("/var/lib/nomad")
		status.HasData = len(entries) > 0
	}

	// Check for config directory
	if info, err := os.Stat("/etc/nomad.d"); err == nil && info.IsDir() {
		entries, _ := os.ReadDir("/etc/nomad.d")
		status.HasConfig = len(entries) > 0
	}

	// Check if user exists
	if _, err := exec.Command("id", "nomad").Output(); err == nil {
		status.UserExists = true
	}

	// Validate config if present
	if status.Installed && status.HasConfig {
		if err := exec.Command("nomad", "config", "validate", "/etc/nomad.d/").Run(); err == nil {
			status.ConfigValid = true
		}
	}

	return status, nil
}

func runDeleteNomad(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if running as root
	if os.Geteuid() != 0 {
		return eos_err.NewUserError("this command must be run as root")
	}

	// Create a context with extended timeout for delete operations
	deleteTimeout := time.Duration(nomadTimeout+300) * time.Second // Add 5 minutes to user timeout
	ctx, cancel := context.WithTimeout(rc.Ctx, deleteTimeout)
	defer cancel()

	// Update the runtime context with extended timeout
	rc.Ctx = ctx

	logger.Info("Starting Nomad removal process",
		zap.Bool("force", nomadForceDelete),
		zap.Bool("keep_data", nomadKeepData),
		zap.Bool("keep_config", nomadKeepConfig),
		zap.Bool("keep_user", nomadKeepUser),
		zap.Int("timeout", nomadTimeout),
		zap.Duration("operation_timeout", deleteTimeout))

	// ASSESS - Check current Nomad status
	logger.Info("Checking current Nomad status")
	status, err := checkNomadDeleteStatus(rc)
	if err != nil {
		logger.Warn("Failed to check Nomad status", zap.Error(err))
		status = &NomadDeleteStatus{} // Use empty status
	}

	// Log detailed status
	logger.Info("Current Nomad installation status",
		zap.Bool("installed", status.Installed),
		zap.Bool("running", status.Running),
		zap.Bool("failed", status.Failed),
		zap.String("version", status.Version),
		zap.String("service_status", status.ServiceStatus),
		zap.Bool("has_data", status.HasData),
		zap.Bool("has_config", status.HasConfig),
		zap.Bool("user_exists", status.UserExists),
		zap.Bool("server_mode", status.ServerMode),
		zap.Bool("client_mode", status.ClientMode),
		zap.String("node_id", status.NodeID),
		zap.Int("cluster_members", len(status.ClusterMembers)),
		zap.Int("running_jobs", len(status.RunningJobs)))

	// Check if anything needs to be removed
	if !status.Installed && !status.HasData && !status.HasConfig && !status.UserExists {
		logger.Info("Nomad is not installed on this system - nothing to remove")
		return nil
	}

	// Show warnings for running jobs/cluster
	if len(status.RunningJobs) > 0 {
		logger.Warn("Nomad has running jobs",
			zap.Int("job_count", len(status.RunningJobs)))
		for _, job := range status.RunningJobs {
			logger.Info("Running job", zap.String("job", job))
		}
	}

	if len(status.ClusterMembers) > 1 {
		logger.Warn("Nomad is part of a cluster",
			zap.Int("member_count", len(status.ClusterMembers)))
		for _, member := range status.ClusterMembers {
			logger.Info("Cluster member", zap.String("member", member))
		}
	}

	// Confirmation prompt
	if !nomadForceDelete {
		prompt := "Are you sure you want to remove Nomad"
		details := []string{}

		if status.HasData && !nomadKeepData {
			details = append(details, "all data will be deleted")
		}
		if status.HasConfig && !nomadKeepConfig {
			details = append(details, "all configurations will be removed")
		}
		if status.UserExists && !nomadKeepUser {
			details = append(details, "the nomad user will be removed")
		}
		if len(status.RunningJobs) > 0 {
			details = append(details, fmt.Sprintf("%d running jobs will be stopped", len(status.RunningJobs)))
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
			logger.Info("Nomad deletion cancelled by user")
			return nil
		}
	}

	// INTERVENE - Apply removal using native removal function
	logger.Info("Applying Nomad removal")

	// P0 FIX: Use the actual working RemoveNomadCompletely function instead of Ansible API
	logger.Info("Removing Nomad using native removal function")

	// Determine if we should keep data
	keepData := nomadKeepData || nomadKeepConfig

	if err := nomad.RemoveNomadCompletely(rc, keepData); err != nil {
		logger.Error("Nomad removal failed", zap.Error(err))
		return fmt.Errorf("nomad removal failed: %w", err)
	}

	logger.Info("Nomad removal completed successfully")

	// EVALUATE - Verify removal
	logger.Info("Verifying Nomad removal")

	// Re-check status after removal
	finalStatus, err := checkNomadDeleteStatus(rc)
	if err != nil {
		logger.Warn("Failed to verify final status", zap.Error(err))
	} else {
		remainingComponents := []string{}

		if finalStatus.Installed {
			remainingComponents = append(remainingComponents, "binary")
		}
		if finalStatus.UserExists && !nomadKeepUser {
			remainingComponents = append(remainingComponents, "user")
		}
		if finalStatus.HasConfig && !nomadKeepConfig {
			remainingComponents = append(remainingComponents, "config")
		}
		if finalStatus.HasData && !nomadKeepData {
			remainingComponents = append(remainingComponents, "data")
		}

		if len(remainingComponents) == 0 {
			logger.Info("Nomad removal completed successfully - all components removed")
		} else {
			logger.Warn("Some Nomad components remain",
				zap.Strings("remaining", remainingComponents))

			// This is only an error if we didn't intend to keep them
			if (finalStatus.HasData && !nomadKeepData) ||
				(finalStatus.HasConfig && !nomadKeepConfig) ||
				(finalStatus.UserExists && !nomadKeepUser) {
				return fmt.Errorf("failed to remove all components: %v", remainingComponents)
			}
		}
	}

	// Show summary
	logger.Info("Nomad removal summary",
		zap.Bool("data_kept", nomadKeepData && finalStatus.HasData),
		zap.Bool("config_kept", nomadKeepConfig && finalStatus.HasConfig),
		zap.Bool("user_kept", nomadKeepUser && finalStatus.UserExists))

	if nomadKeepData || nomadKeepConfig {
		logger.Info("terminal prompt: Preserved components can be manually removed later if needed")
	}

	logger.Info("terminal prompt: You can now safely reinstall Nomad with 'eos create nomad'")

	return nil
}

func init() {
	DeleteNomadCmd.Flags().BoolVarP(&nomadForceDelete, "force", "f", false, "Force deletion without confirmation prompt")
	DeleteNomadCmd.Flags().BoolVar(&nomadKeepData, "keep-data", false, "Preserve Nomad data directory (/var/lib/nomad)")
	DeleteNomadCmd.Flags().BoolVar(&nomadKeepConfig, "keep-config", false, "Preserve Nomad configuration (/etc/nomad.d)")
	DeleteNomadCmd.Flags().BoolVar(&nomadKeepUser, "keep-user", false, "Preserve nomad system user account")
	DeleteNomadCmd.Flags().IntVar(&nomadTimeout, "timeout", 30, "Timeout in seconds for graceful node drain")

	// Register the command with the delete command
	DeleteCmd.AddCommand(DeleteNomadCmd)
}
