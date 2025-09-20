// cmd/create/consul_native.go

package create

import (
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/bootstrap"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/consul"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_err"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var CreateConsulCmd = &cobra.Command{
	Use:   "consul",
	Short: "Install and configure HashiCorp Consul directly (without )",
	Long: `Install and configure HashiCorp Consul using native installation methods.

This command installs Consul directly without using configuration management tools,
eliminating circular dependencies and simplifying the installation process.

INSTALLATION METHODS:
• Repository: Use HashiCorp's official APT repository (default)
• Binary: Download and install binary directly from releases.hashicorp.com

FEATURES:
• Service discovery with DNS and HTTP API
• Health monitoring and automatic failover
• Consul Connect service mesh ready
• Automatic Vault integration if available
• Production-ready security settings
• Idempotent installation (safe to run multiple times)

CONFIGURATION:
• HTTP API on port ` + fmt.Sprintf("%d", shared.PortConsul) + `
• DNS service discovery on port 8600
• gRPC on port 8502
• UI enabled by default
• Consul Connect enabled for service mesh

EXAMPLES:
  # Install Consul using APT repository (recommended)
  eos create consul

  # Install specific version via binary download
  eos create consul --binary --version 1.17.1

  # Force reconfiguration of existing Consul
  eos create consul --force

  # Clean install (removes existing data)
  eos create consul --clean

  # Install with custom datacenter name
  eos create consul --datacenter production

  # Install without Vault integration
  eos create consul --no-vault-integration`,
	RunE: eos_cli.Wrap(runCreateConsul),
}

var (
	consulDatacenter string
	consulNoVault    bool
	consulDebug      bool
	consulForce      bool
	consulClean      bool
	consulBinary     bool
	consulVersion    string
)

func runCreateConsul(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if running as root
	if os.Geteuid() != 0 {
		return eos_err.NewUserError("this command must be run as root")
	}

	// Check if system is bootstrapped
	if err := bootstrap.RequireBootstrap(rc); err != nil {
		// Bootstrap not required for fundamental services like Consul
		logger.Debug("System not bootstrapped, continuing with Consul installation")
	}

	logger.Info("Starting native Consul installation",
		zap.String("datacenter", consulDatacenter),
		zap.Bool("vault_integration", !consulNoVault),
		zap.Bool("use_binary", consulBinary),
		zap.String("version", consulVersion))

	// Create installation config
	installConfig := &consul.InstallConfig{
		Version:          consulVersion,
		Datacenter:       consulDatacenter,
		ServerMode:       true,
		BootstrapExpect:  1,
		UIEnabled:        true,
		ConnectEnabled:   true,
		VaultIntegration: !consulNoVault,
		LogLevel:         getConsulLogLevel(consulDebug),
		BindAddr:         "0.0.0.0",
		ClientAddr:       "0.0.0.0",
		ForceReinstall:   consulForce,
		CleanInstall:     consulClean,
		UseRepository:    !consulBinary, // Use repository by default
	}

	// Use unified installer
	installer := consul.NewConsulInstaller(rc, installConfig)

	// ASSESS, INTERVENE, EVALUATE pattern is handled inside the installer
	if err := installer.Install(); err != nil {
		return fmt.Errorf("consul installation failed: %w", err)
	}

	logger.Info("terminal prompt: ✅ Consul installation completed successfully!")
	logger.Info(fmt.Sprintf("terminal prompt: Web UI available at: http://<server-ip>:%d", shared.PortConsul))
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: Next steps:")
	logger.Info("terminal prompt: 1. Check status: consul members")
	logger.Info("terminal prompt: 2. View logs: journalctl -u consul -f")
	logger.Info(fmt.Sprintf("terminal prompt: 3. Access UI: http://localhost:%d/ui", shared.PortConsul))

	return nil
}

func getConsulLogLevel(debug bool) string {
	if debug {
		return "DEBUG"
	}
	return "INFO"
}

func init() {
	CreateConsulCmd.Flags().StringVarP(&consulDatacenter, "datacenter", "d", "dc1",
		"Datacenter name for Consul cluster")
	CreateConsulCmd.Flags().BoolVar(&consulNoVault, "no-vault-integration", false,
		"Disable automatic Vault integration")
	CreateConsulCmd.Flags().BoolVar(&consulDebug, "debug", false,
		"Enable debug logging for Consul")
	CreateConsulCmd.Flags().BoolVar(&consulForce, "force", false,
		"Force reconfiguration even if Consul is running")
	CreateConsulCmd.Flags().BoolVar(&consulClean, "clean", false,
		"Remove all data and perform clean installation")
	CreateConsulCmd.Flags().BoolVar(&consulBinary, "binary", false,
		"Use direct binary download instead of APT repository")
	CreateConsulCmd.Flags().StringVar(&consulVersion, "version", "latest",
		"Consul version to install (default: latest)")

	// Register the command with the create command
	CreateCmd.AddCommand(CreateConsulCmd)
}
