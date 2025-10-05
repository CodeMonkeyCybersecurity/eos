// cmd/delete/vault.go

package delete

import (
	"fmt"
	"os"
	"os/exec"

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

⚠️  WARNING: This will remove ALL Vault data including:
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

	// ASSESS - Check if Vault is installed
	vaultInstalled := false
	if _, err := exec.LookPath("vault"); err == nil {
		vaultInstalled = true
		logger.Info("Vault binary found")

		// Get version
		if output, err := exec.Command("vault", "version").Output(); err == nil {
			logger.Info("Current Vault version", zap.String("version", string(output)))
		}
	} else {
		logger.Info("Vault binary not found in PATH")
	}

	// Check if Vault service is running
	vaultRunning := false
	if output, err := exec.Command("systemctl", "is-active", "vault").Output(); err == nil {
		status := string(output)
		if status == "active\n" {
			vaultRunning = true
			logger.Info("Vault service is currently active")
		}
	}

	// If nothing is installed, no need to proceed
	if !vaultInstalled && !vaultRunning {
		// Check if config/data dirs exist
		hasData := false
		checkPaths := []string{"/etc/vault.d", "/opt/vault", "/var/lib/vault"}
		for _, path := range checkPaths {
			if _, err := os.Stat(path); err == nil {
				hasData = true
				break
			}
		}

		if !hasData {
			logger.Info("Vault is not installed and no data directories found")
			return nil
		}
	}

	// Confirmation prompt unless forced
	if !vaultForceDelete {
		prompt := `⚠️  WARNING: You are about to PERMANENTLY DELETE Vault and ALL its data!

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
	}

	// INTERVENE - Stop Vault services
	logger.Info("Stopping Vault services")

	// Stop vault service
	if err := exec.Command("systemctl", "stop", "vault").Run(); err != nil {
		logger.Warn("Failed to stop vault service (may not be running)", zap.Error(err))
	}

	// Stop vault-agent if present
	if err := exec.Command("systemctl", "stop", "vault-agent").Run(); err != nil {
		logger.Debug("vault-agent not running or doesn't exist")
	}

	// Disable services
	exec.Command("systemctl", "disable", "vault").Run()
	exec.Command("systemctl", "disable", "vault-agent").Run()

	// Kill any remaining vault processes
	exec.Command("pkill", "-f", "vault").Run()

	// Determine distro for package-specific cleanup
	distro := "debian" // Default
	if _, err := os.Stat("/etc/redhat-release"); err == nil {
		distro = "rhel"
	}

	logger.Info("Detected distribution", zap.String("distro", distro))

	// P0 FIX: Use the comprehensive Purge function
	logger.Info("Purging all Vault files and configurations")
	removed, errs := vault.Purge(rc, distro)

	// Log what was removed
	if len(removed) > 0 {
		logger.Info("Removed Vault files",
			zap.Int("count", len(removed)),
			zap.Strings("files", removed))
	}

	// Log any errors but don't fail completely
	if len(errs) > 0 {
		logger.Warn("Some files could not be removed",
			zap.Int("error_count", len(errs)))
		for path, err := range errs {
			logger.Debug("Failed to remove path",
				zap.String("path", path),
				zap.Error(err))
		}
	}

	// Remove Vault package if installed via package manager
	logger.Info("Removing Vault package")
	if distro == "debian" {
		exec.Command("apt-get", "remove", "--purge", "-y", "vault").Run()
		exec.Command("apt-get", "autoremove", "-y").Run()
	} else if distro == "rhel" {
		exec.Command("dnf", "remove", "-y", "vault").Run()
	}

	// Remove vault user if exists
	logger.Info("Removing vault user and group")
	exec.Command("userdel", "-r", "vault").Run()
	exec.Command("groupdel", "vault").Run()

	// Reload systemd
	exec.Command("systemctl", "daemon-reload").Run()

	// EVALUATE - Verify removal
	logger.Info("Verifying Vault removal")

	stillPresent := []string{}

	if _, err := exec.LookPath("vault"); err == nil {
		stillPresent = append(stillPresent, "vault binary still in PATH")
	}

	checkDirs := map[string]string{
		"/etc/vault.d":   "config directory",
		"/opt/vault":     "data directory",
		"/var/lib/vault": "data directory",
		"/var/log/vault": "log directory",
	}

	for dir, desc := range checkDirs {
		if _, err := os.Stat(dir); err == nil {
			stillPresent = append(stillPresent, fmt.Sprintf("%s (%s)", desc, dir))
		}
	}

	if len(stillPresent) > 0 {
		logger.Warn("Some Vault components still present",
			zap.Strings("remaining", stillPresent))
		logger.Info("You may need to manually remove these components")
	} else {
		logger.Info("✅ Vault removal completed successfully - all components removed")
	}

	logger.Info("Vault removal process finished",
		zap.Int("files_removed", len(removed)),
		zap.Int("errors", len(errs)),
		zap.Int("remaining_components", len(stillPresent)))

	return nil
}

func init() {
	VaultCmd.Flags().BoolVarP(&vaultForceDelete, "force", "f", false, "Force deletion without confirmation (DANGEROUS)")

	// Register the command with the delete command
	DeleteCmd.AddCommand(VaultCmd)
}
