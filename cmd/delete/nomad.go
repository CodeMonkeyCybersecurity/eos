// cmd/delete/nomad.go

package delete

import (
	"fmt"
	"os"
	"strings"

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

func runDeleteNomad(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if running as root
	if os.Geteuid() != 0 {
		return eos_err.NewUserError("this command must be run as root")
	}

	logger.Info("Starting Nomad removal process",
		zap.Bool("force", nomadForceDelete),
		zap.Bool("keep_data", nomadKeepData),
		zap.Bool("keep_config", nomadKeepConfig),
		zap.Bool("keep_user", nomadKeepUser))

	// Create uninstaller configuration
	config := &nomad.UninstallConfig{
		Force:        nomadForceDelete,
		RemoveData:   !nomadKeepData,
		RemoveConfig: !nomadKeepConfig,
		RemoveUser:   !nomadKeepUser,
		Timeout:      nomadTimeout,
	}

	// Create uninstaller
	uninstaller := nomad.NewNomadUninstaller(rc, config)

	// ASSESS - Check current state
	state, err := uninstaller.Assess()
	if err != nil {
		return fmt.Errorf("failed to assess Nomad installation: %w", err)
	}

	// Early exit if nothing installed
	if !state.BinaryInstalled && !state.DataExists && !state.ConfigExists && !state.UserExists {
		logger.Info("Nomad is not installed - nothing to remove")
		return nil
	}

	// Show warnings for running jobs/cluster
	if len(state.RunningJobs) > 0 {
		logger.Warn("Nomad has running jobs", zap.Int("count", len(state.RunningJobs)))
		for _, job := range state.RunningJobs {
			logger.Info("Running job", zap.String("job", job))
		}
	}

	if len(state.ClusterMembers) > 1 {
		logger.Warn("Nomad is part of a cluster", zap.Int("members", len(state.ClusterMembers)))
		for _, member := range state.ClusterMembers {
			logger.Info("Cluster member", zap.String("member", member))
		}
	}

	// User confirmation
	if !nomadForceDelete {
		if err := promptNomadConfirmation(rc, state, logger); err != nil {
			return err
		}
	}

	// INTERVENE - Execute uninstallation
	if err := uninstaller.Uninstall(); err != nil {
		return fmt.Errorf("nomad uninstallation failed: %w", err)
	}

	logger.Info("Nomad removal process completed successfully")
	logger.Info("terminal prompt: You can now safely reinstall Nomad with 'eos create nomad'")
	return nil
}

func promptNomadConfirmation(rc *eos_io.RuntimeContext, state *nomad.UninstallState, logger otelzap.LoggerWithCtx) error {
	prompt := "Are you sure you want to remove Nomad"
	details := []string{}

	if state.DataExists && !nomadKeepData {
		details = append(details, "all data will be deleted")
	}
	if state.ConfigExists && !nomadKeepConfig {
		details = append(details, "all configurations will be removed")
	}
	if state.UserExists && !nomadKeepUser {
		details = append(details, "the nomad user will be removed")
	}
	if len(state.RunningJobs) > 0 {
		details = append(details, fmt.Sprintf("%d running jobs will be stopped", len(state.RunningJobs)))
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
