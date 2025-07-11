// cmd/create/consul.go

package create

import (
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/consul/config"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/consul/detect"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/consul/display"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/consul/health"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/consul/install"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/consul/scripts"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/consul/service"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/consul/setup"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/consul/systemd"
	consulvault "github.com/CodeMonkeyCybersecurity/eos/pkg/consul/vault"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var CreateConsulCmd = &cobra.Command{
	Use:   "consul",
	Short: "Install and configure Consul with service discovery and scaling features",
	Long: `Install and configure HashiCorp Consul with advanced features for service discovery,
health monitoring, and scaling readiness.

FEATURES:
• Service discovery with DNS and HTTP API
• Health monitoring and automatic failover
• Consul Connect service mesh ready
• Automatic Vault integration if available
• Scaling-ready configuration
• Comprehensive audit logging
• Production-ready security settings

CONFIGURATION:
• HTTP API on port ` + fmt.Sprintf("%d", shared.PortConsul) + ` (instead of default 8500)
• Consul Connect enabled for service mesh
• UI enabled for management
• Automatic Vault service registration
• DNS service discovery on port 8600

EXAMPLES:
  # Install Consul with default configuration
  eos create consul

  # Install Consul with custom datacenter name
  eos create consul --datacenter production

  # Install without Vault integration
  eos create consul --no-vault-integration

  # Install with debug logging enabled
  eos create consul --debug --datacenter staging`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		log := otelzap.Ctx(rc.Ctx)
		log.Info("Starting advanced Consul installation and configuration",
			zap.String("datacenter", datacenterName),
			zap.Bool("vault_integration", !disableVaultIntegration),
			zap.Bool("debug_logging", enableDebugLogging))

		// Check if running as root
		if os.Geteuid() != 0 {
			return fmt.Errorf("this command must be run as root")
		}

		// Install Consul binary
		if err := install.Binary(rc); err != nil {
			return fmt.Errorf("install Consul binary: %w", err)
		}

		// Create system user and directories
		if err := setup.SystemUser(rc); err != nil {
			return fmt.Errorf("setup system user: %w", err)
		}

		// Detect if Vault is available for integration
		vaultAvailable := false
		if !disableVaultIntegration {
			vaultAvailable = detect.VaultInstallation(rc)
		}

		// Generate main Consul configuration
		cfg := &config.ConsulConfig{
			DatacenterName:     datacenterName,
			EnableDebugLogging: enableDebugLogging,
			VaultAvailable:     vaultAvailable,
		}
		if err := config.Generate(rc, cfg); err != nil {
			return fmt.Errorf("generate Consul config: %w", err)
		}

		// Generate Vault service registration if Vault is available
		if vaultAvailable {
			if err := consulvault.GenerateServiceConfig(rc); err != nil {
				log.Warn("Failed to create Vault service registration", zap.Error(err))
			}
		}

		// Create systemd service
		if err := systemd.CreateService(rc); err != nil {
			return fmt.Errorf("create systemd service: %w", err)
		}

		// Create helper script
		if err := scripts.CreateHelper(rc); err != nil {
			return fmt.Errorf("create helper script: %w", err)
		}

		// Start and enable service
		if err := service.Start(rc); err != nil {
			return fmt.Errorf("start Consul service: %w", err)
		}

		// Wait for service to be ready
		if err := health.WaitForReady(rc); err != nil {
			return fmt.Errorf("wait for Consul ready: %w", err)
		}

		// Display success information
		display.InstallationSummary(rc, vaultAvailable)

		return nil
	}),
}

// TODO move to pkg/ to DRY up this code base but putting it with other similar functions
var (
	datacenterName          string
	disableVaultIntegration bool
	enableDebugLogging      bool
)

func init() {
	CreateConsulCmd.Flags().StringVarP(&datacenterName, "datacenter", "d", "dc1", "Datacenter name for Consul cluster")
	CreateConsulCmd.Flags().BoolVar(&disableVaultIntegration, "no-vault-integration", false, "Disable automatic Vault integration")
	CreateConsulCmd.Flags().BoolVar(&enableDebugLogging, "debug", false, "Enable debug logging for Consul")

	// Register the command with the create command
	CreateCmd.AddCommand(CreateConsulCmd)
}