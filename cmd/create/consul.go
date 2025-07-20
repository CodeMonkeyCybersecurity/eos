// cmd/create/consul.go

package create

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var CreateConsulCmd = &cobra.Command{
	Use:   "consul",
	Short: "Install and configure HashiCorp Consul using SaltStack",
	Long: `Install and configure HashiCorp Consul using SaltStack orchestration.

This command provides a complete Consul deployment including:
- Installation of Consul binary via HashiCorp repository
- Service discovery and mesh networking configuration
- TLS certificate generation and management
- Service configuration and systemd integration
- Health monitoring and automatic failover
- Consul Connect service mesh ready configuration
- Automatic Vault integration if available
- Comprehensive audit logging and security settings

The deployment is managed entirely through SaltStack states, ensuring
consistent and repeatable installations.

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
	RunE: eos.Wrap(runCreateConsul),
}

// TODO move to pkg/ to DRY up this code base but putting it with other similar functions
var (
	datacenterName          string
	disableVaultIntegration bool
	enableDebugLogging      bool
)

func runCreateConsul(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if running as root
	if os.Geteuid() != 0 {
		return fmt.Errorf("this command must be run as root")
	}

	logger.Info("Starting SaltStack-based Consul installation and configuration",
		zap.String("datacenter", datacenterName),
		zap.Bool("vault_integration", !disableVaultIntegration),
		zap.Bool("debug_logging", enableDebugLogging))

	// ASSESS - Check if SaltStack is available
	saltCallPath, err := exec.LookPath("salt-call")
	if err != nil {
		logger.Error("SaltStack is required for Consul installation. Please install SaltStack first using 'eos create saltstack'")
		return fmt.Errorf("saltstack is required for consul installation - salt-call not found in PATH")
	}
	logger.Info("SaltStack detected", zap.String("salt_call", saltCallPath))

	// INTERVENE - Apply SaltStack state
	logger.Info("Applying SaltStack state for Consul installation")
	
	// Prepare Salt pillar data
	pillarData := map[string]interface{}{
		"consul": map[string]interface{}{
			"datacenter":       datacenterName,
			"log_level":        func() string { if enableDebugLogging { return "DEBUG" } else { return "INFO" } }(),
			"server_mode":      true,
			"bootstrap_expect": 1,
			"bind_addr":        "0.0.0.0", 
			"client_addr":      "0.0.0.0",
			"ui_enabled":       true,
			"connect_enabled":  true,
			"vault_integration": !disableVaultIntegration,
			"http_port":        shared.PortConsul,
			"dns_port":         8600,
			"grpc_port":        8502,
		},
	}

	pillarJSON, err := json.Marshal(pillarData)
	if err != nil {
		return fmt.Errorf("failed to marshal pillar data: %w", err)
	}

	// Execute Salt state
	saltArgs := []string{
		"--local",
		"--file-root=/opt/eos/salt/states",
		"--pillar-root=/opt/eos/salt/pillar",
		"state.apply",
		"hashicorp.consul",
		"--output=json",
		"--output-indent=2",
		fmt.Sprintf("pillar='%s'", string(pillarJSON)),
	}

	logger.Info("Executing Salt state",
		zap.String("state", "hashicorp.consul"),
		zap.Strings("args", saltArgs))

	output, err := exec.Command("salt-call", saltArgs...).CombinedOutput()
	if err != nil {
		logger.Error("Salt state execution failed",
			zap.Error(err),
			zap.String("output", string(output)))
		return fmt.Errorf("salt state execution failed: %w", err)
	}

	logger.Info("Salt state executed successfully",
		zap.String("output", string(output)))

	// EVALUATE - Verify installation
	logger.Info("Verifying Consul installation")
	
	// Check if consul binary is available
	if _, err := exec.LookPath("consul"); err != nil {
		return fmt.Errorf("consul binary not found after installation: %w", err)
	}

	// Check if consul service is running
	if err := exec.Command("systemctl", "is-active", "consul").Run(); err != nil {
		logger.Warn("Consul service is not running, attempting to start it")
		if err := exec.Command("systemctl", "start", "consul").Run(); err != nil {
			return fmt.Errorf("failed to start consul service: %w", err)
		}
	}

	// Display success information
	logger.Info("Consul installation completed successfully",
		zap.String("datacenter", datacenterName),
		zap.String("mode", "server"),
		zap.String("management", "SaltStack"))

	logger.Info("Consul is now running",
		zap.String("web_ui", fmt.Sprintf("http://localhost:%d", shared.PortConsul)),
		zap.String("api", fmt.Sprintf("http://localhost:%d/v1/", shared.PortConsul)),
		zap.String("dns", "localhost:8600"))

	return nil
}

func init() {
	CreateConsulCmd.Flags().StringVarP(&datacenterName, "datacenter", "d", "dc1", "Datacenter name for Consul cluster")
	CreateConsulCmd.Flags().BoolVar(&disableVaultIntegration, "no-vault-integration", false, "Disable automatic Vault integration")
	CreateConsulCmd.Flags().BoolVar(&enableDebugLogging, "debug", false, "Enable debug logging for Consul")

	// Register the command with the create command
	CreateCmd.AddCommand(CreateConsulCmd)
}
