// cmd/delete/vault.go
//
// This file provides the CLI interface for removing HashiCorp Vault.
// Business logic is in pkg/vault/uninstall.go following the Eos architecture pattern.

package delete

import (
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var VaultCmd = &cobra.Command{
	Use:   "vault",
	Short: "Remove HashiCorp Vault and all associated data",
	Long: `Remove HashiCorp Vault completely from the system.

This command will:
- Stop the Vault service and agent
- Remove the Vault package and binary
- Delete configuration files (/etc/vault.d)
- Remove data directories (/opt/vault)
- Clean up TLS certificates
- Remove log files
- Remove systemd service files
- Clean up repository configuration (APT/DNF)

WARNING: This will remove ALL Vault data including:
- Encryption keys
- Sealed/unsealed data
- All secrets stored in Vault
- TLS certificates

BACKUP YOUR DATA before proceeding!

EXAMPLES:
  # Remove Vault (asks for confirmation)
  eos delete vault

  # Remove Vault without confirmation (use with caution)
  eos delete vault --yes

SAFETY:
  This command removes ALL Vault data permanently.
  By default, it asks for confirmation before deletion.
  Use --yes to skip the confirmation prompt.`,
	RunE: eos_cli.Wrap(runDeleteVault),
}

var (
	vaultSkipConfirmation bool
)

func runDeleteVault(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if running as root
	currentUID := os.Geteuid()
	logger.Debug("Checking user permissions", zap.Int("euid", currentUID))

	if currentUID != 0 {
		logger.Error("Insufficient permissions - root required", zap.Int("euid", currentUID))
		return eos_err.NewUserError("this command must be run as root")
	}

	logger.Info("Starting Vault removal process",
		zap.Bool("skip_confirmation", vaultSkipConfirmation),
		zap.String("command", "delete vault"))

	// Create uninstaller configuration
	// Force is always true - we always do complete removal
	logger.Debug("Creating uninstaller configuration",
		zap.Bool("skip_confirmation", vaultSkipConfirmation),
		zap.Bool("remove_data", true),
		zap.Bool("remove_user", true))

	config := &vault.UninstallConfig{
		Force:      true, // Always force complete removal
		RemoveData: true,
		RemoveUser: true,
	}

	// Create uninstaller
	logger.Debug("Initializing Vault uninstaller")
	uninstaller := vault.NewVaultUninstaller(rc, config)
	logger.Info("Uninstaller initialized successfully")

	// Perform initial assessment
	logger.Info("Assessing current Vault installation state")
	state, err := uninstaller.Assess()
	if err != nil {
		logger.Error("Assessment failed", zap.Error(err))
		return fmt.Errorf("failed to assess Vault installation: %w", err)
	}

	logger.Info("Assessment completed",
		zap.Bool("binary_installed", state.BinaryInstalled),
		zap.Bool("service_running", state.ServiceRunning),
		zap.Bool("service_enabled", state.ServiceEnabled),
		zap.Bool("config_exists", state.ConfigExists),
		zap.Bool("data_exists", state.DataExists),
		zap.Bool("user_exists", state.UserExists),
		zap.Bool("package_installed", state.PackageInstalled),
		zap.Int("existing_paths", len(state.ExistingPaths)),
		zap.String("version", state.Version))

	// If nothing is installed, return early
	if !state.BinaryInstalled && !state.ServiceRunning && len(state.ExistingPaths) == 0 {
		logger.Info("Vault is not installed and no data directories found - nothing to remove")
		return nil
	}

	// Simple confirmation prompt unless --yes is used
	// NOTE: We removed the root token/unseal key verification as it was too aggressive
	// and blocked deletion of broken/inaccessible Vault installations
	if !vaultSkipConfirmation {
		logger.Debug("Prompting user for confirmation")
		if err := promptForConfirmation(rc, logger, state); err != nil {
			if err.Error() == "user cancelled" {
				logger.Info("Deletion cancelled by user")
				return nil
			}
			logger.Error("Confirmation prompt failed", zap.Error(err))
			return err
		}
		logger.Info("User confirmed deletion - proceeding")
	} else {
		logger.Info("--yes flag set - skipping confirmation prompt")
	}

	// Execute uninstallation (will use already-assessed state)
	logger.Info("Beginning Vault uninstallation process")
	if err := uninstaller.Uninstall(); err != nil {
		logger.Error("Vault uninstallation failed", zap.Error(err))
		return fmt.Errorf("vault uninstallation failed: %w", err)
	}

	logger.Info("Vault removal process completed successfully")
	return nil
}

// promptForConfirmation handles user confirmation for deletion
func promptForConfirmation(rc *eos_io.RuntimeContext, logger otelzap.LoggerWithCtx, state *vault.UninstallState) error {
	// Show what will be deleted
	logger.Info("terminal prompt: ═══════════════════════════════════════════════════════════════════")
	logger.Info("terminal prompt: COMPONENTS TO BE DELETED")
	logger.Info("terminal prompt: ═══════════════════════════════════════════════════════════════════")

	if state.BinaryInstalled {
		logger.Info(fmt.Sprintf("terminal prompt:  Binary: %s", state.Version))
	}
	if state.ServiceRunning || state.ServiceEnabled {
		status := "installed"
		if state.ServiceRunning {
			status = "RUNNING"
		}
		logger.Info(fmt.Sprintf("terminal prompt:  Service: %s", status))
	}
	if len(state.ExistingPaths) > 0 {
		logger.Info(fmt.Sprintf("terminal prompt:  Data: %d directories", len(state.ExistingPaths)))
	}
	if state.UserExists {
		logger.Info("terminal prompt:  User & Group: vault")
	}
	logger.Info("terminal prompt: ═══════════════════════════════════════════════════════════════════")
	logger.Info("terminal prompt: ")

	prompt := `WARNING: This will PERMANENTLY DELETE Vault and ALL its data!

This includes ALL secrets, encryption keys, TLS certificates, and configuration.
This action CANNOT be undone!

Continue? [y/N] `

	logger.Info("terminal prompt: " + prompt)
	logger.Debug("Waiting for user input (y/N)")

	response, err := eos_io.ReadInput(rc)
	if err != nil {
		logger.Error("Failed to read user input", zap.Error(err))
		return fmt.Errorf("failed to read user input: %w", err)
	}

	logger.Debug("User response received", zap.String("response", response))

	if response != "y" && response != "Y" {
		logger.Info("Vault deletion cancelled by user")
		return fmt.Errorf("user cancelled")
	}

	logger.Info("Confirmation accepted - deletion authorized")
	return nil
}

func init() {
	VaultCmd.Flags().BoolVarP(&vaultSkipConfirmation, "yes", "y", false, "Skip confirmation prompt (use with caution)")

	// Register the command with the delete command
	DeleteCmd.AddCommand(VaultCmd)
}
