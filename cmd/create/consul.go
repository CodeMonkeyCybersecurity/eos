// cmd/create/consul_native.go

package create

import (
	"fmt"
	"os"
	"strings"

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
	Short: "Install and configure HashiCorp Consul using native methods",
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
  # Install Consul server using APT repository (recommended)
  eos create consul

  # Install Consul client (agent mode)
  eos create consul --client

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
	consulBindAddr   string // CRITICAL: Missing flag causing error message confusion
	consulNoVault    bool
	consulDebug      bool
	consulForce      bool
	consulClean      bool
	consulBinary     bool
	consulVersion    string
	consulServer     bool
	consulClient     bool
)

func runCreateConsul(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if running as root
	if os.Geteuid() != 0 {
		return eos_err.NewUserError("this command must be run as root")
	}

	// Determine server/client mode with clear conflict handling
	serverMode := consulServer
	if consulServer && consulClient {
		return eos_err.NewUserError("cannot specify both --server and --client flags. Choose one.\n" +
			"  --server: Run as Consul server (stores data, participates in consensus)\n" +
			"  --client: Run as Consul client (agent mode, forwards to servers)")
	}
	if !consulServer && !consulClient {
		// Default to server mode if neither flag is specified
		serverMode = true
		logger.Info("Defaulting to server mode (neither --server nor --client specified)")
	}

	// Warn about destructive operations with explicit confirmation
	if consulClean {
		logger.Warn("--clean flag specified: This will DELETE all existing Consul data")
		logger.Info("terminal prompt: Type 'yes' to confirm or Ctrl+C to cancel: ")

		var confirmation string
		fmt.Scanln(&confirmation)
		if strings.ToLower(strings.TrimSpace(confirmation)) != "yes" {
			return eos_err.NewUserError("clean install cancelled by user (did not type 'yes')")
		}
		logger.Info("Clean install confirmed")
	}

	logger.Info("Starting native Consul installation",
		zap.String("datacenter", consulDatacenter),
		zap.Bool("server_mode", serverMode),
		zap.Bool("vault_integration", !consulNoVault),
		zap.Bool("use_binary", consulBinary),
		zap.String("version", consulVersion),
		zap.String("bind_addr", consulBindAddr))

	// Create installation config
	installConfig := &consul.InstallConfig{
		Version:          consulVersion,
		Datacenter:       consulDatacenter,
		ServerMode:       serverMode,
		BootstrapExpect:  1,
		UIEnabled:        true,
		ConnectEnabled:   true,
		VaultIntegration: !consulNoVault,
		LogLevel:         getConsulLogLevel(consulDebug),
		BindAddr:         consulBindAddr, // Use user-specified or auto-detect
		ClientAddr:       "0.0.0.0",
		ForceReinstall:   consulForce,
		CleanInstall:     consulClean,
		UseRepository:    !consulBinary, // Use repository by default
	}

	// Use unified installer
	installer, err := consul.NewConsulInstaller(rc, installConfig)
	if err != nil {
		return fmt.Errorf("failed to create consul installer: %w", err)
	}

	// ASSESS, INTERVENE, EVALUATE pattern is handled inside the installer
	if err := installer.Install(); err != nil {
		return fmt.Errorf("consul installation failed: %w", err)
	}

	// CRITICAL: Success message is printed AFTER Install() returns successfully
	// Install() includes verification, so if we reach here, Consul is actually working
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: ✓ Consul installation completed successfully!")
	logger.Info("terminal prompt: ")
	logger.Info(fmt.Sprintf("terminal prompt: Web UI: http://<server-ip>:%d/ui", shared.PortConsul))
	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: Quick Start:")
	logger.Info("terminal prompt:   consul members              # View cluster members")
	logger.Info("terminal prompt:   journalctl -u consul -f     # View live logs")
	logger.Info(fmt.Sprintf("terminal prompt:   curl http://localhost:%d/v1/agent/self  # Test API", shared.PortConsul))

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
	CreateConsulCmd.Flags().StringVar(&consulBindAddr, "bind-addr", "",
		"Network address to bind to (auto-detects primary interface if not specified)")
	CreateConsulCmd.Flags().BoolVar(&consulServer, "server", false,
		"Install as Consul server (default if neither --server nor --client specified)")
	CreateConsulCmd.Flags().BoolVar(&consulClient, "client", false,
		"Install as Consul client (agent mode)")
	CreateConsulCmd.Flags().BoolVar(&consulNoVault, "no-vault-integration", false,
		"Disable automatic Vault integration")
	CreateConsulCmd.Flags().BoolVar(&consulDebug, "debug", false,
		"Enable debug logging for Consul")
	CreateConsulCmd.Flags().BoolVar(&consulForce, "force", false,
		"Force reconfiguration even if Consul is running (backs up existing config)")
	CreateConsulCmd.Flags().BoolVar(&consulClean, "clean", false,
		"DESTRUCTIVE: Remove all data and perform clean installation (requires confirmation)")
	CreateConsulCmd.Flags().BoolVar(&consulBinary, "binary", false,
		"Use direct binary download instead of APT repository")
	CreateConsulCmd.Flags().StringVar(&consulVersion, "version", "latest",
		"Consul version to install (default: latest)")

	// Register the command with the create command
	CreateCmd.AddCommand(CreateConsulCmd)
}
