// cmd/read/vault_status.go
package read

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/vault"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// VaultStatusCmd shows comprehensive Vault status including Consul integration
var VaultStatusCmd = &cobra.Command{
	Use:   "vault-status",
	Short: "Show comprehensive Vault status and integration",
	Long: `Display comprehensive information about Vault installation and integrations.

This command shows:
- Vault version and installation status
- Service running status
- Seal status
- Storage backend configuration
- Consul integration status
- Health check information

EXAMPLES:
  # Show full Vault status
  eos read vault-status

  # Show Vault status (shorter alias)
  eos read vault status
`,
	RunE: eos_cli.Wrap(runVaultStatus),
}

func runVaultStatus(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: ================================================================================")
	logger.Info("terminal prompt: Vault Status and Integration Report")
	logger.Info("terminal prompt: ================================================================================")
	logger.Info("terminal prompt: ")

	// Check if Vault is installed
	vaultPath, err := exec.LookPath("vault")
	if err != nil {
		logger.Info("terminal prompt: === Vault Installation ===")
		logger.Info("terminal prompt:   Status: ✗ Vault not installed")
		logger.Info("terminal prompt:   Install with: sudo eos create vault")
		return nil
	}

	logger.Info("terminal prompt: === Vault Installation ===")
	logger.Info("terminal prompt:   Status: ✓ Vault installed")
	logger.Info("terminal prompt:   Binary: " + vaultPath)

	// Get Vault version
	versionOutput, err := exec.Command("vault", "version").Output()
	if err == nil {
		version := strings.TrimSpace(string(versionOutput))
		logger.Info("terminal prompt:   Version: " + version)
	}
	logger.Info("terminal prompt: ")

	// Check service status
	logger.Info("terminal prompt: === Service Status ===")
	serviceOutput, err := exec.Command("systemctl", "is-active", "vault").Output()
	if err != nil {
		logger.Info("terminal prompt:   Status: ✗ Vault service not running")
		logger.Info("terminal prompt:   Start with: sudo systemctl start vault")
	} else {
		serviceStatus := strings.TrimSpace(string(serviceOutput))
		if serviceStatus == "active" {
			logger.Info("terminal prompt:   Status: ✓ Vault service is running")

			// Get Vault status (seal status, etc.)
			displayVaultSealStatus(logger)
		} else {
			logger.Info(fmt.Sprintf("terminal prompt:   Status: %s", serviceStatus))
		}
	}
	logger.Info("terminal prompt: ")

	// Check Consul integration
	logger.Info("terminal prompt: === Consul Integration ===")
	consulStatus, err := vault.CheckConsulIntegration(rc.Ctx)
	if err != nil {
		logger.Warn("Failed to check Consul integration", zap.Error(err))
		logger.Info("terminal prompt:   Unable to determine Consul integration status")
	} else {
		displayConsulIntegrationStatus(logger, consulStatus)
	}

	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: ================================================================================")

	return nil
}

// displayVaultSealStatus shows Vault seal status information
func displayVaultSealStatus(logger otelzap.LoggerWithCtx) {
	// Try to get vault status
	statusOutput, err := exec.Command("vault", "status", "-format=json").Output()
	if err != nil {
		// Vault might not be accessible, show basic info
		logger.Info("terminal prompt:   Seal Status: Unable to determine (vault CLI unavailable)")
		return
	}

	// Parse basic seal status from output
	statusStr := string(statusOutput)
	if strings.Contains(statusStr, `"sealed":false`) {
		logger.Info("terminal prompt:   Seal Status: ✓ Unsealed")
	} else if strings.Contains(statusStr, `"sealed":true`) {
		logger.Info("terminal prompt:   Seal Status: ✗ Sealed")
		logger.Info("terminal prompt:   Unseal with: vault operator unseal")
	}

	if strings.Contains(statusStr, `"initialized":true`) {
		logger.Info("terminal prompt:   Initialized: ✓ yes")
	} else if strings.Contains(statusStr, `"initialized":false`) {
		logger.Info("terminal prompt:   Initialized: ✗ no")
		logger.Info("terminal prompt:   Initialize with: vault operator init")
	}
}

// displayConsulIntegrationStatus shows Consul integration details
func displayConsulIntegrationStatus(logger otelzap.LoggerWithCtx, status *vault.ConsulIntegrationStatus) {
	// Overall status
	if status.IntegrationHealthy {
		logger.Info("terminal prompt:   Status: ✓ Fully integrated with Consul")
	} else if status.UsingConsulStorage {
		logger.Info("terminal prompt:   Status: ⚠ Using Consul storage with issues")
	} else {
		logger.Info("terminal prompt:   Status: Not using Consul storage")
	}

	// Consul availability
	logger.Info(fmt.Sprintf("terminal prompt:   Consul Installed:  %s", formatCheckMark(status.ConsulInstalled)))
	logger.Info(fmt.Sprintf("terminal prompt:   Consul Running:    %s", formatCheckMark(status.ConsulRunning)))

	// Storage backend
	logger.Info(fmt.Sprintf("terminal prompt:   Storage Backend:   %s", getStorageBackendDisplay(status)))

	if status.UsingConsulStorage {
		if status.ConsulAddress != "" {
			logger.Info("terminal prompt:   Consul Address:    " + status.ConsulAddress)
		}
		if status.ConsulPath != "" {
			logger.Info("terminal prompt:   Storage Path:      " + status.ConsulPath)
		}

		logger.Info(fmt.Sprintf("terminal prompt:   Service Registration: %s", formatCheckMark(status.RegisteredInConsul)))

		if status.HealthChecksEnabled {
			logger.Info("terminal prompt:   Health Checks:     ✓ Enabled")
		}
	}

	// Show configuration file location
	if status.ConfigurationPath != "" {
		logger.Info("terminal prompt:   Configuration:     " + status.ConfigurationPath)
	}

	// Show issues
	if len(status.Issues) > 0 {
		logger.Info("terminal prompt:   ")
		logger.Info("terminal prompt:   Issues:")
		for _, issue := range status.Issues {
			logger.Info("terminal prompt:     • " + issue)
		}
	}

	// Recommendations
	if status.UsingConsulStorage && !status.ConsulRunning {
		logger.Info("terminal prompt:   ")
		logger.Info("terminal prompt:   ⚠ Warning: Vault is configured to use Consul, but Consul is not running")
		logger.Info("terminal prompt:   Start Consul with: sudo systemctl start consul")
	}

	if status.UsingConsulStorage && status.ConsulRunning && !status.RegisteredInConsul {
		logger.Info("terminal prompt:   ")
		logger.Info("terminal prompt:   Recommendation: Register Vault in Consul")
		logger.Info("terminal prompt:   Run: sudo eos sync --vault --consul")
	}
}

// formatCheckMark returns a formatted checkmark or X
func formatCheckMark(b bool) string {
	if b {
		return "✓ yes"
	}
	return "✗ no"
}

// getStorageBackendDisplay returns a display string for the storage backend
func getStorageBackendDisplay(status *vault.ConsulIntegrationStatus) string {
	if status.UsingConsulStorage {
		if status.ConsulRunning {
			return "Consul (connected)"
		}
		return "Consul (not connected)"
	}
	return "Other (not Consul)"
}

func init() {
	ReadCmd.AddCommand(VaultStatusCmd)
}
