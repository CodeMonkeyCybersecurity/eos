// cmd/update/wazuh_ossec.go

package update

import (
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/wazuh/ossec"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var ossecUpdateOpts ossec.UpdateOptions

// UpdateWazuhOssecCmd handles Wazuh ossec.conf configuration updates
var UpdateWazuhOssecCmd = &cobra.Command{
	Use:   "wazuh-ossec-conf",
	Short: "Update Wazuh ossec.conf configuration safely",
	Long: `Safely update Wazuh ossec.conf configuration with validation, backup, and rollback capabilities.

This command provides a human-safe way to modify Wazuh configuration sections including:
- Global settings (timeouts, logging)
- Remote connections (ports, protocols)
- Vulnerability detection
- Integrations (webhooks)
- Syscheck (FIM)
- Syslog forwarding
- Active response
- Log file monitoring
- Wodle modules

Examples:
  # Update from configuration file
  eos update wazuh-ossec-conf --config-file config.yaml

  # Dry run to preview changes
  eos update wazuh-ossec-conf --config-file config.yaml --dry-run

  # Update with custom backup location
  eos update wazuh-ossec-conf --backup-path /backup/ossec.conf.bak --config-file config.yaml

  # Quick vulnerability detection update
  eos update wazuh-ossec-conf --vuln-enabled yes --vuln-interval 60m`,
	RunE: eos_cli.Wrap(runWazuhOssecUpdate),
}

func init() {
	// Core flags
	UpdateWazuhOssecCmd.Flags().BoolVar(&ossecUpdateOpts.Backup, "backup", true, "Create backup before modifying")
	UpdateWazuhOssecCmd.Flags().BoolVar(&ossecUpdateOpts.DryRun, "dry-run", false, "Preview changes without applying")
	UpdateWazuhOssecCmd.Flags().BoolVar(&ossecUpdateOpts.Validate, "validate", true, "Validate XML after changes")
	UpdateWazuhOssecCmd.Flags().BoolVar(&ossecUpdateOpts.Force, "force", false, "Force update even if validation warnings")
	UpdateWazuhOssecCmd.Flags().BoolVar(&ossecUpdateOpts.RestartWazuh, "restart", false, "Automatically restart Wazuh after update")

	// Configuration file
	UpdateWazuhOssecCmd.Flags().StringVar(&ossecUpdateOpts.ConfigFile, "config-file", "", "Path to configuration YAML file")
	UpdateWazuhOssecCmd.Flags().StringVar(&ossecUpdateOpts.BackupPath, "backup-path", "", "Custom backup file path")

	// Individual settings - vulnerability detection (most common use case)
	UpdateWazuhOssecCmd.Flags().String("vuln-enabled", "", "Enable vulnerability detection: yes/no")
	UpdateWazuhOssecCmd.Flags().String("vuln-interval", "", "Feed update interval (e.g., 60m)")
	UpdateWazuhOssecCmd.Flags().String("vuln-index", "", "Index vulnerability data: yes/no")

	// Register with UpdateCmd
	UpdateCmd.AddCommand(UpdateWazuhOssecCmd)
}

func runWazuhOssecUpdate(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) (err error) {
	logger := otelzap.Ctx(rc.Ctx)
	defer rc.End(&err)

	logger.Info("Starting Wazuh ossec.conf update")

	// ASSESS - Check prerequisites
	logger.Info("Phase 1: ASSESS - Checking prerequisites")

	// Check if running as root
	if os.Geteuid() != 0 {
		return fmt.Errorf("this command must be run as root (sudo)")
	}

	// Check if Wazuh is installed
	ossecPath := "/var/ossec/etc/ossec.conf"
	if _, err := os.Stat(ossecPath); os.IsNotExist(err) {
		return fmt.Errorf("wazuh not installed or ossec.conf not found at %s", ossecPath)
	}

	// Parse flags into UpdateOptions
	if err := parseOssecFlags(rc, cmd); err != nil {
		return fmt.Errorf("error parsing flags: %w", err)
	}

	// Load configuration from file if provided
	if ossecUpdateOpts.ConfigFile != "" {
		logger.Info("Loading configuration from file", zap.String("file", ossecUpdateOpts.ConfigFile))
		if err := ossec.LoadConfigFromYAML(rc, ossecUpdateOpts.ConfigFile, &ossecUpdateOpts); err != nil {
			return fmt.Errorf("error loading config file: %w", err)
		}
	}

	// Validate we have something to update
	if !ossec.HasUpdates(&ossecUpdateOpts) {
		logger.Warn("No configuration changes specified")
		return fmt.Errorf("no configuration changes specified - provide --config-file or specific flags")
	}

	// INTERVENE - Apply updates
	logger.Info("Phase 2: INTERVENE - Applying configuration updates")

	// Create backup
	var backupFile string
	if ossecUpdateOpts.Backup {
		backupFile, err = ossec.CreateBackup(rc, ossecPath, ossecUpdateOpts.BackupPath)
		if err != nil {
			return fmt.Errorf("error creating backup: %w", err)
		}
		logger.Info("Created backup", zap.String("backup_file", backupFile))
	}

	// Read current configuration
	currentConfig, err := ossec.ReadConfigFile(ossecPath)
	if err != nil {
		return fmt.Errorf("error reading ossec.conf: %w", err)
	}

	// Apply updates using pkg/wazuh/ossec
	updatedConfig, err := ossec.ApplyUpdates(rc, currentConfig, &ossecUpdateOpts)
	if err != nil {
		return fmt.Errorf("error applying updates: %w", err)
	}

	// Validate new configuration
	if ossecUpdateOpts.Validate {
		if err := ossec.ValidateXML(rc, updatedConfig); err != nil {
			if !ossecUpdateOpts.Force {
				logger.Error("Validation failed", zap.Error(err))
				return fmt.Errorf("validation failed: %w (use --force to override)", err)
			}
			logger.Warn("Validation warnings detected, continuing with --force", zap.Error(err))
		}
	}

	// Dry run mode - show diff and exit
	if ossecUpdateOpts.DryRun {
		logger.Info("DRY RUN MODE - Showing changes that would be applied")
		showOssecDiff(rc, currentConfig, updatedConfig)
		logger.Info("No changes applied (dry run mode)")
		return nil
	}

	// Write updated configuration
	if err := ossec.WriteConfigFile(rc, ossecPath, updatedConfig); err != nil {
		return fmt.Errorf("error writing ossec.conf: %w", err)
	}

	logger.Info("Configuration updated successfully")

	// EVALUATE - Test and verify
	logger.Info("Phase 3: EVALUATE - Testing configuration")

	// Test configuration with Wazuh
	if err := ossec.TestWazuhConfig(rc); err != nil {
		logger.Error("Wazuh configuration test failed", zap.Error(err))
		if ossecUpdateOpts.Backup {
			logger.Warn("Rolling back to previous configuration")
			if err := ossec.RestoreBackup(rc, backupFile, ossecPath); err != nil {
				return fmt.Errorf("rollback failed: %w", err)
			}
			logger.Info("Rolled back successfully")
		}
		return fmt.Errorf("configuration test failed: %w", err)
	}

	logger.Info("Configuration validated by Wazuh")

	// Restart Wazuh if requested
	if ossecUpdateOpts.RestartWazuh {
		if err := ossec.RestartWazuhServices(rc); err != nil {
			return fmt.Errorf("error restarting Wazuh: %w", err)
		}
		logger.Info("Wazuh services restarted successfully")
	} else {
		logger.Info("Configuration updated - restart Wazuh services to apply changes: sudo systemctl restart wazuh-manager")
	}

	logger.Info("Wazuh ossec.conf update complete")
	return nil
}

// parseOssecFlags parses command-line flags into UpdateOptions
func parseOssecFlags(rc *eos_io.RuntimeContext, cmd *cobra.Command) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Parse vulnerability detection flags
	if cmd.Flags().Changed("vuln-enabled") {
		if ossecUpdateOpts.Vulnerability == nil {
			ossecUpdateOpts.Vulnerability = &ossec.VulnConfig{}
		}
		val, _ := cmd.Flags().GetString("vuln-enabled")
		ossecUpdateOpts.Vulnerability.Enabled = val
		logger.Debug("Parsed vuln-enabled flag", zap.String("value", val))
	}

	if cmd.Flags().Changed("vuln-interval") {
		if ossecUpdateOpts.Vulnerability == nil {
			ossecUpdateOpts.Vulnerability = &ossec.VulnConfig{}
		}
		val, _ := cmd.Flags().GetString("vuln-interval")
		ossecUpdateOpts.Vulnerability.FeedUpdateInterval = val
		logger.Debug("Parsed vuln-interval flag", zap.String("value", val))
	}

	if cmd.Flags().Changed("vuln-index") {
		if ossecUpdateOpts.Vulnerability == nil {
			ossecUpdateOpts.Vulnerability = &ossec.VulnConfig{}
		}
		val, _ := cmd.Flags().GetString("vuln-index")
		ossecUpdateOpts.Vulnerability.IndexStatus = val
		logger.Debug("Parsed vuln-index flag", zap.String("value", val))
	}

	return nil
}

// showOssecDiff displays a simple diff of the changes (kept in cmd/ as it's display-only)
func showOssecDiff(rc *eos_io.RuntimeContext, original, updated []byte) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Configuration changes:")
	logger.Info("====================")
	logger.Info("Original size: %d bytes", zap.Int("bytes", len(original)))
	logger.Info("Updated size: %d bytes", zap.Int("bytes", len(updated)))
	logger.Info("Diff: %d bytes", zap.Int("diff", len(updated)-len(original)))
	logger.Info("")
	logger.Info("Note: Use a diff tool to see detailed changes")
	logger.Info("Example: diff /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.backup.<timestamp>")
}
