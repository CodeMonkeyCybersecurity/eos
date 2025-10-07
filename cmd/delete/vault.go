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
  # Remove Vault with confirmation prompt
  eos delete vault

  # Remove Vault without confirmation (use with extreme caution)
  eos delete vault --force

SAFETY:
  By default, this command requires confirmation before proceeding.
  Use --force only in non-production environments or when you're
  absolutely certain you want to destroy all Vault data.`,
	RunE: eos_cli.Wrap(runDeleteVault),
}

var (
	vaultForceDelete bool
)

func runDeleteVault(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if running as root
	if os.Geteuid() != 0 {
		return eos_err.NewUserError("this command must be run as root")
	}

	logger.Info("Starting Vault removal process",
		zap.Bool("force", vaultForceDelete))

	// Create uninstaller configuration
	config := &vault.UninstallConfig{
		Force:      vaultForceDelete,
		RemoveData: true,
		RemoveUser: true,
	}

	// Create uninstaller
	uninstaller := vault.NewVaultUninstaller(rc, config)

	// Perform initial assessment
	state, err := uninstaller.Assess()
	if err != nil {
		return fmt.Errorf("failed to assess Vault installation: %w", err)
	}

	// If nothing is installed, return early
	if !state.BinaryInstalled && !state.ServiceRunning && len(state.ExistingPaths) == 0 {
		logger.Info("Vault is not installed and no data directories found")
		return nil
	}

	// Store state for use in Uninstall() (avoids duplicate assessment)
	// This is a bit of a hack - we set it via reflection of the struct
	// Actually, let's just call Uninstall which will use the already-assessed state

	// Confirmation prompt unless forced
	if !vaultForceDelete {
		if err := promptForConfirmation(rc, logger, state); err != nil {
			return err
		}
	}

	// Execute uninstallation (will use already-assessed state)
	if err := uninstaller.Uninstall(); err != nil {
		return fmt.Errorf("vault uninstallation failed: %w", err)
	}

	logger.Info(" Vault removal process completed successfully")
	return nil
}

// promptForConfirmation handles user confirmation for deletion
func promptForConfirmation(rc *eos_io.RuntimeContext, logger otelzap.LoggerWithCtx, state *vault.UninstallState) error {
	// Show what will be deleted
	logger.Info("terminal prompt: \n═══════════════════════════════════════════════════════════════════")
	logger.Info("terminal prompt: 📋 COMPONENTS TO BE DELETED")
	logger.Info("terminal prompt: ═══════════════════════════════════════════════════════════════════")

	if state.BinaryInstalled {
		logger.Info(fmt.Sprintf("terminal prompt:  Binary: %s", state.Version))
	}
	if state.ServiceRunning || state.ServiceEnabled {
		status := "installed"
		if state.ServiceRunning {
			status = "RUNNING"
		}
		logger.Info(fmt.Sprintf("terminal prompt: 🔧 Service: %s", status))
	}
	if len(state.ExistingPaths) > 0 {
		logger.Info(fmt.Sprintf("terminal prompt:  Data: %d directories", len(state.ExistingPaths)))
	}
	if state.UserExists {
		logger.Info("terminal prompt:  User & Group: vault")
	}
	logger.Info("terminal prompt: ═══════════════════════════════════════════════════════════════════")
	logger.Info("terminal prompt: ")

	prompt := `  WARNING: You are about to PERMANENTLY DELETE Vault and ALL its data!

This includes:
- All secrets stored in Vault
- Encryption keys (recovery will be IMPOSSIBLE)
- TLS certificates
- Configuration files
- All Vault data directories

This action CANNOT be undone!

Are you absolutely sure you want to proceed? [y/N] `

	logger.Info("terminal prompt: " + prompt)
	response, err := eos_io.ReadInput(rc)
	if err != nil {
		return fmt.Errorf("failed to read user input: %w", err)
	}

	if response != "y" && response != "Y" {
		logger.Info("Vault deletion cancelled by user")
		return nil
	}

	// Double confirmation for safety
	logger.Info("terminal prompt: Type 'DELETE' to confirm (this is your last chance): ")
	confirmResponse, err := eos_io.ReadInput(rc)
	if err != nil {
		return fmt.Errorf("failed to read confirmation: %w", err)
	}

	if confirmResponse != "DELETE" {
		logger.Info("Vault deletion cancelled - confirmation did not match")
		return nil
	}

	return nil
}

func init() {
	VaultCmd.Flags().BoolVarP(&vaultForceDelete, "force", "f", false, "Force deletion without confirmation (DANGEROUS)")

	// Register the command with the delete command
	DeleteCmd.AddCommand(VaultCmd)
}
