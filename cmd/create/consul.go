// cmd/create/consul.go

package create

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
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

IDEMPOTENCY:
By default, this command will not reinstall or reconfigure Consul if it's
already running successfully. Use --force to reconfigure an existing
installation or --clean to completely remove and reinstall.

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

  # Force reconfiguration of existing Consul
  eos create consul --force

  # Clean install (removes existing data)
  eos create consul --clean

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
	forceReinstall          bool
	cleanInstall            bool
)

// ConsulStatus represents the current state of Consul installation
type ConsulStatus struct {
	Installed      bool
	Running        bool
	Failed         bool
	ConfigValid    bool
	Version        string
	ServiceStatus  string
	LastError      string
}

func checkConsulStatus(rc *eos_io.RuntimeContext) (*ConsulStatus, error) {
	logger := otelzap.Ctx(rc.Ctx)
	status := &ConsulStatus{}

	// Check if Consul binary exists
	if consulPath, err := exec.LookPath("consul"); err == nil {
		status.Installed = true
		logger.Debug("Consul binary found", zap.String("path", consulPath))
		
		// Get version
		if output, err := exec.Command("consul", "version").Output(); err == nil {
			lines := strings.Split(string(output), "\n")
			if len(lines) > 0 {
				status.Version = strings.TrimSpace(lines[0])
			}
		}
	}

	// Check service status
	if output, err := exec.Command("systemctl", "is-active", "consul").Output(); err == nil {
		status.ServiceStatus = strings.TrimSpace(string(output))
		status.Running = (status.ServiceStatus == "active")
	} else {
		// Check if service is in failed state
		if exec.Command("systemctl", "is-failed", "consul").Run() == nil {
			status.Failed = true
			status.ServiceStatus = "failed"
			
			// Get last error from journal
			if output, err := exec.Command("journalctl", "-u", "consul", "-n", "10", "--no-pager").Output(); err == nil {
				status.LastError = string(output)
			}
		}
	}

	// Check config validity if Consul is installed
	if status.Installed {
		if _, err := os.Stat("/etc/consul.d/consul.hcl"); err == nil {
			if err := exec.Command("consul", "validate", "/etc/consul.d/").Run(); err == nil {
				status.ConfigValid = true
			}
		}
	}

	return status, nil
}

func runCreateConsul(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if running as root
	if os.Geteuid() != 0 {
		return eos_err.NewUserError("this command must be run as root")
	}

	logger.Info("Starting Consul installation process",
		zap.String("datacenter", datacenterName),
		zap.Bool("vault_integration", !disableVaultIntegration),
		zap.Bool("debug_logging", enableDebugLogging),
		zap.Bool("force", forceReinstall),
		zap.Bool("clean", cleanInstall))

	// ASSESS - Check current Consul status
	logger.Info("Checking current Consul status")
	status, err := checkConsulStatus(rc)
	if err != nil {
		logger.Warn("Failed to check Consul status", zap.Error(err))
	} else {
		logger.Info("Current Consul status",
			zap.Bool("installed", status.Installed),
			zap.Bool("running", status.Running),
			zap.Bool("failed", status.Failed),
			zap.Bool("config_valid", status.ConfigValid),
			zap.String("version", status.Version),
			zap.String("service_status", status.ServiceStatus))
	}

	// Idempotency check - if Consul is running successfully and no force flags
	if status.Running && status.ConfigValid && !forceReinstall && !cleanInstall {
		logger.Info("Consul is already running successfully",
			zap.String("version", status.Version),
			zap.String("status", status.ServiceStatus))
		logger.Info("terminal prompt: Consul is already installed and running. Use --force to reconfigure or --clean for a fresh install.")
		return nil
	}

	// If Consul is in failed state and no force flags
	if status.Failed && !forceReinstall && !cleanInstall {
		logger.Error("Consul service is in failed state",
			zap.String("last_error", status.LastError))
		logger.Info("terminal prompt: Consul is installed but in a failed state. Check logs with 'journalctl -xeu consul.service'")
		logger.Info("terminal prompt: Use --force to reconfigure or --clean for a fresh install.")
		return eos_err.NewUserError("Consul is in failed state. Use --force or --clean to proceed")
	}

	// Check if SaltStack is available
	saltCallPath, err := exec.LookPath("salt-call")
	if err != nil {
		logger.Error("SaltStack is required for Consul installation")
		return eos_err.NewUserError("saltstack is required for consul installation - please install SaltStack first using 'eos create saltstack'")
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
			"force_reinstall":  forceReinstall,
			"clean_install":    cleanInstall,
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
		"pillar=" + string(pillarJSON),
	}

	logger.Info("Executing Salt state",
		zap.String("state", "hashicorp.consul"),
		zap.Strings("args", saltArgs))

	output, err := exec.Command("salt-call", saltArgs...).CombinedOutput()
	if err != nil {
		logger.Error("Salt state execution failed",
			zap.Error(err),
			zap.String("output", string(output)))
		
		// Parse the output to provide more helpful error messages
		if strings.Contains(string(output), "consul.service failed") {
			logger.Error("Consul service failed to start. Check configuration and logs")
			logger.Info("terminal prompt: Run 'journalctl -xeu consul.service' to see detailed error logs")
		}
		
		return fmt.Errorf("salt state execution failed: %w", err)
	}

	logger.Debug("Salt state output", zap.String("output", string(output)))

	// EVALUATE - Verify installation
	logger.Info("Verifying Consul installation")
	
	// Re-check status after installation
	newStatus, err := checkConsulStatus(rc)
	if err != nil {
		return fmt.Errorf("failed to verify Consul status: %w", err)
	}

	if !newStatus.Installed {
		return fmt.Errorf("consul binary not found after installation")
	}

	if !newStatus.Running {
		logger.Warn("Consul service is not running after installation",
			zap.String("service_status", newStatus.ServiceStatus))
		
		// Try to start it one more time
		logger.Info("Attempting to start Consul service")
		if err := exec.Command("systemctl", "start", "consul").Run(); err != nil {
			logger.Error("Failed to start Consul service",
				zap.Error(err))
			logger.Info("terminal prompt: Check logs with 'journalctl -xeu consul.service' for details")
			return fmt.Errorf("failed to start consul service: %w", err)
		}
		
		// Wait a moment and check again
		exec.Command("sleep", "2").Run()
		finalStatus, _ := checkConsulStatus(rc)
		if !finalStatus.Running {
			return fmt.Errorf("consul service failed to start")
		}
	}

	// Display success information
	logger.Info("Consul installation completed successfully",
		zap.String("datacenter", datacenterName),
		zap.String("version", newStatus.Version),
		zap.String("mode", "server"),
		zap.String("management", "SaltStack"))

	logger.Info("Consul is now running",
		zap.String("web_ui", fmt.Sprintf("http://localhost:%d", shared.PortConsul)),
		zap.String("api", fmt.Sprintf("http://localhost:%d/v1/", shared.PortConsul)),
		zap.String("dns", "localhost:8600"))

	// Show cluster status
	if output, err := exec.Command("consul", "members").Output(); err == nil {
		logger.Info("Consul cluster members",
			zap.String("members", string(output)))
	}

	return nil
}

func init() {
	CreateConsulCmd.Flags().StringVarP(&datacenterName, "datacenter", "d", "dc1", "Datacenter name for Consul cluster")
	CreateConsulCmd.Flags().BoolVar(&disableVaultIntegration, "no-vault-integration", false, "Disable automatic Vault integration")
	CreateConsulCmd.Flags().BoolVar(&enableDebugLogging, "debug", false, "Enable debug logging for Consul")
	CreateConsulCmd.Flags().BoolVar(&forceReinstall, "force", false, "Force reconfiguration even if Consul is running")
	CreateConsulCmd.Flags().BoolVar(&cleanInstall, "clean", false, "Remove all data and perform clean installation")

	// Register the command with the create command
	CreateCmd.AddCommand(CreateConsulCmd)
}