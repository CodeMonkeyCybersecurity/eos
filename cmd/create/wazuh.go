// cmd/create/wazuh.go
// Configure Wazuh integration with external webhook (Iris)
//
// Created by Code Monkey Cybersecurity
// ABN: 77 177 673 061

package create

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/privilege_check"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/utils"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/wazuh"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/wazuh/agents"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/wazuh/config"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/wazuh/credentials"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/wazuh/docker"
	wazuhsetup "github.com/CodeMonkeyCybersecurity/eos/pkg/wazuh/setup"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Webhook integration flags
var (
	webhookOut  bool
	hookURL     string
	webhookPort string
	autoRestart bool
)

// createWazuhCmd configures Wazuh webhook integration
var createWazuhCmd = &cobra.Command{
	Use:   "wazuh",
	Short: "Configure Wazuh integration with external webhook",
	Long: `Sets up Wazuh to send alerts to an external webhook (like Iris).

This command will:
- Install custom-iris integration scripts
- Create .env file with webhook URL and auth token
- Set correct permissions for Wazuh
- Update ossec.conf with integration block
- Install Python dependencies
- Optionally restart Wazuh manager

Usage:
  eos create wazuh --webhook-out                          # Interactive mode
  eos create wazuh --webhook-out --hook-url=http://...    # With URL
  eos create wazuh --webhook-out --auto-restart           # Auto-restart Wazuh`,
	RunE: eos.Wrap(runCreateWazuh),
}

func init() {
	CreateCmd.AddCommand(createWazuhCmd)
	createWazuhCmd.Flags().BoolVar(&webhookOut, "webhook-out", false, "Configure webhook integration")
	createWazuhCmd.Flags().StringVar(&hookURL, "hook-url", "", "Webhook URL (e.g., http://192.168.1.100:8080/webhook)")
	createWazuhCmd.Flags().StringVar(&webhookPort, "port", "8080", "Webhook port (default: 8080)")
	createWazuhCmd.Flags().BoolVar(&autoRestart, "auto-restart", false, "Automatically restart wazuh-manager")
}

// runCreateWazuh orchestrates the webhook integration setup
func runCreateWazuh(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	if !webhookOut {
		return fmt.Errorf("use --webhook-out flag to configure webhook integration")
	}

	// Parse flags into config
	config := wazuhsetup.DefaultConfig()
	config.AutoRestart = autoRestart

	// Delegate to pkg/wazuh/setup
	return wazuhsetup.Install(rc, config, hookURL)
}

// Configuration flags moved to pkg/wazuh/config
var wazuhFlags = config.DefaultFlags()

func init() {
	CreateCmd.AddCommand(CreateWazuhCmd)
	CreateWazuhCmd.Flags().BoolVar(&wazuhFlags.IgnoreHardwareCheck, "ignore", false, "Ignore Wazuh hardware requirements check")
	CreateWazuhCmd.Flags().BoolVar(&wazuhFlags.OverwriteInstall, "overwrite", false, "Overwrite existing Wazuh installation")

	// Add mapping command
	CreateCmd.AddCommand(mappingCmd)
}

// CreateWazuhCmd deploys Wazuh (all-in-one) installation
var CreateWazuhCmd = &cobra.Command{
	Use:     "wazuh",
	Aliases: []string{"wazuh"},
	Short:   "Deploy Wazuh (Wazuh all-in-one) with optional hardware check override",
	Long: `Deploy Wazuh (Wazuh all-in-one) security monitoring platform.

Installs the full Wazuh stack (server, dashboard, and indexer) using the official quickstart script.
By default, this checks your system's hardware (4GB RAM, 2+ cores). Use --ignore to bypass this check.

FEATURES:
• Complete Wazuh all-in-one deployment
• Security monitoring and incident response
• Log analysis and threat detection
• Compliance reporting (PCI-DSS, HIPAA, GDPR)
• File integrity monitoring
• Vulnerability assessment
• Web dashboard for management

REQUIREMENTS:
• 4GB RAM minimum (use --ignore to bypass)
• 2+ CPU cores minimum (use --ignore to bypass)
• 10GB free disk space
• Supported Linux distributions (Debian, RHEL-based)

EXAMPLES:
  # Install with default hardware checks
  eos create wazuh

  # Install ignoring hardware requirements
  eos create wazuh --ignore

  # Install with overwrite of existing installation
  eos create wazuh --overwrite

  # Install with both options
  eos create wazuh --ignore --overwrite`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		log := otelzap.Ctx(rc.Ctx)

		if err := platform.RequireLinuxDistro(rc, []string{"debian", "rhel"}); err != nil {
			log.Fatal("Unsupported Linux distro", zap.Error(err))
		}

		tmpDir := "/tmp"
		scriptURL := "https://packages.wazuh.com/4.13/wazuh-install.sh"
		scriptPath := filepath.Join(tmpDir, "wazuh-install.sh")

		log.Info("Downloading Wazuh installer", zap.String("url", scriptURL))
		if err := utils.DownloadFile(scriptPath, scriptURL); err != nil {
			return fmt.Errorf("failed to download installer: %w", err)
		}
		if err := os.Chmod(scriptPath, shared.DirPermStandard); err != nil {
			return fmt.Errorf("failed to make script executable: %w", err)
		}

		args = []string{"-a"}
		if wazuhFlags.IgnoreHardwareCheck {
			log.Info("Ignoring hardware checks (passing -i)")
			args = append(args, "-i")
		}
		if wazuhFlags.OverwriteInstall {
			log.Info("Overwriting existing installation (passing -o)")
			args = append(args, "-o")
		}

		log.Info("Running Wazuh installer script")
		cmdArgs := append([]string{scriptPath}, args...)
		installCmd := exec.Command("bash", cmdArgs...)
		installCmd.Stdout = os.Stdout
		installCmd.Stderr = os.Stderr
		if err := installCmd.Run(); err != nil {
			return fmt.Errorf("installation failed: %w", err)
		}
		log.Info("Wazuh installation completed")

		log.Info("Attempting to extract Wazuh admin credentials")
		if err := credentials.ExtractWazuhPasswords(rc); err != nil {
			log.Warn("Could not extract Wazuh credentials", zap.Error(err))
		}

		log.Info("Disabling Wazuh repo updates")
		distro := platform.DetectLinuxDistro(rc)
		switch distro {
		case "debian", "ubuntu":
			cmd := exec.Command("sed", "-i", "s/^deb /#deb /", "/etc/apt/sources.list.d/wazuh.list")
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			if err := cmd.Run(); err != nil {
				log.Warn("Failed to comment out Wazuh APT repo", zap.Error(err))
			} else {
				log.Info("Wazuh APT repo commented out")
				_ = exec.Command("apt", "update").Run()
			}
		default:
			cmd := exec.Command("sed", "-i", "s/^enabled=1/enabled=0/", "/etc/yum.repos.d/wazuh.repo")
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			if err := cmd.Run(); err != nil {
				log.Warn("Failed to disable Wazuh yum repo", zap.Error(err))
			} else {
				log.Info("Wazuh yum repo disabled")
			}
		}

		log.Info("Wazuh (Wazuh) setup complete")
		log.Info("To access the Wazuh Dashboard:")
		log.Info("Run this on your **local machine** (not over SSH):")
		log.Info("    firefox https://$(hostname -I | awk '{print $1}')")
		log.Info("Or forward port with:")
		log.Info("    ssh -L 8443:localhost:443 user@your-server")
		log.Info("Then browse: https://localhost:8443")
		log.Info("To harden this install, run: `eos harden wazuh`")

		return nil
	}),
}

// mappingCmd suggests best agent package for each endpoint
var mappingCmd = &cobra.Command{
	Use:   "mapping",
	Short: "Suggest the best agent package for each endpoint",
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		// Use the wazuh package to access ResolveConfig and Authenticate
		// This avoids the circular import issue
		cfg, err := wazuh.ResolveConfig(rc)
		if err != nil {
			return fmt.Errorf("failed to resolve config: %w", err)
		}

		// Create authentication function
		authenticateFunc := func(rc *eos_io.RuntimeContext, cfg interface{}) (string, error) {
			if wazuhCfg, ok := cfg.(*wazuh.Config); ok {
				return wazuh.Authenticate(rc, wazuhCfg)
			}
			return "", fmt.Errorf("invalid config type")
		}

		return agents.RunMapping(rc, cfg, authenticateFunc)
	}),
}

func init() {

	// Set up flags for dockerDeployCmd
	dockerDeployCmd.Flags().StringP("version", "v", "", "Wazuh version to deploy (e.g., 4.10.1)")
	dockerDeployCmd.Flags().Bool("single-node", false, "Deploy as single-node")
	dockerDeployCmd.Flags().Bool("multi-node", false, "Deploy as multi-node")
	dockerDeployCmd.Flags().String("proxy", "", "Proxy address for certificate generation")
	dockerDeployCmd.Flags().IntP("port", "p", 8011, "External port for Wazuh dashboard")
	dockerDeployCmd.Flags().BoolP("force", "f", false, "Force deployment without prompts")

	// Set up flags for wazuhCredentialsCmd
	wazuhCredentialsCmd.Flags().String("admin-password", "", "New admin password")
	wazuhCredentialsCmd.Flags().String("kibana-password", "", "New Kibana dashboard password")
	wazuhCredentialsCmd.Flags().String("api-password", "", "New API password")
	wazuhCredentialsCmd.Flags().String("deploy-type", "", "Deployment type (single-node or multi-node)")
	wazuhCredentialsCmd.Flags().BoolP("interactive", "i", false, "Interactive mode with prompts")

	// Set up flags for cleanupCmd
	cleanupCmd.Flags().BoolP("force", "f", false, "Skip confirmation prompts")
	cleanupCmd.Flags().Bool("remove-data", false, "Remove volumes and persistent data")
}

// dockerDeployCmd deploys Wazuh using Docker containers
var dockerDeployCmd = &cobra.Command{
	Use:     "docker",
	Aliases: []string{"container"},
	Short:   "Deploy Wazuh using Docker containers",
	Long: `Deploy Wazuh using Docker containers with automatic setup.

This command handles the complete Docker-based Wazuh deployment process:
- Clones the official Wazuh Docker repository
- Configures deployment type (single-node or multi-node)
- Generates SSL certificates
- Sets up proxy compatibility
- Configures port mappings for Hecate compatibility

Examples:
  eos create wazuh deploy docker --version 4.10.1 --single-node
  eos create wazuh deploy docker --version 4.10.1 --multi-node --proxy proxy.example.com
  eos create wazuh deploy docker --version 4.10.1 --port 8011`,

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		// Check privileges
		privilegeManager := privilege_check.NewPrivilegeManager(nil)
		if err := privilegeManager.CheckSudoOnly(rc); err != nil {
			logger.Error("Root privileges required for Docker deployment", zap.Error(err))
			return err
		}

		// Get flag values
		version, _ := cmd.Flags().GetString("version")
		singleNode, _ := cmd.Flags().GetBool("single-node")
		multiNode, _ := cmd.Flags().GetBool("multi-node")
		proxyAddress, _ := cmd.Flags().GetString("proxy")
		port, _ := cmd.Flags().GetInt("port")
		force, _ := cmd.Flags().GetBool("force")

		// Determine deployment type
		deployType := ""
		if singleNode && multiNode {
			return fmt.Errorf("cannot specify both --single-node and --multi-node")
		} else if singleNode {
			deployType = "single-node"
		} else if multiNode {
			deployType = "multi-node"
		}

		logger.Info("Starting Wazuh Docker deployment",
			zap.String("version", version),
			zap.String("deploy_type", deployType),
			zap.String("proxy", proxyAddress),
			zap.Int("port", port))

		return docker.RunDeployment(rc, version, deployType, proxyAddress, port, force)
	}),
}

// wazuhCredentialsCmd changes default Wazuh credentials
var wazuhCredentialsCmd = &cobra.Command{
	Use:     "credentials",
	Aliases: []string{"creds", "passwords"},
	Short:   "Change default Wazuh credentials",
	Long: `Change default Wazuh credentials with secure password hashing.

This command helps change the default passwords for:
- Admin user (indexer password)
- Kibana dashboard user
- API user

The passwords are automatically hashed using bcrypt for security.

Examples:
  eos create wazuh deploy credentials --interactive
  eos create wazuh deploy credentials --admin-password "newpass" --deploy-type single-node`,

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		// Get flag values
		adminPassword, _ := cmd.Flags().GetString("admin-password")
		kibanaPassword, _ := cmd.Flags().GetString("kibana-password")
		apiPassword, _ := cmd.Flags().GetString("api-password")
		deployType, _ := cmd.Flags().GetString("deploy-type")
		interactive, _ := cmd.Flags().GetBool("interactive")

		logger.Info("Changing Wazuh credentials",
			zap.String("deploy_type", deployType),
			zap.Bool("interactive", interactive))

		return docker.RunCredentialsChange(rc, adminPassword, kibanaPassword, apiPassword, deployType, interactive)
	}),
}

// cleanupCmd removes Wazuh Docker deployment
var cleanupCmd = &cobra.Command{
	Use:     "cleanup",
	Aliases: []string{"remove", "uninstall"},
	Short:   "Remove Wazuh Docker deployment",
	Long: `Remove Wazuh Docker deployment and optionally clean up data.

This command safely removes the Wazuh Docker deployment:
- Stops all containers
- Removes containers and networks
- Optionally removes volumes and data

Examples:
  eos create wazuh deploy cleanup                   # Remove deployment, keep data
  eos create wazuh deploy cleanup --remove-data    # Remove deployment and data
  eos create wazuh deploy cleanup --force          # Skip confirmation`,

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		logger := otelzap.Ctx(rc.Ctx)

		// Get flag values
		force, _ := cmd.Flags().GetBool("force")
		removeData, _ := cmd.Flags().GetBool("remove-data")

		logger.Info("Cleaning up Wazuh deployment",
			zap.Bool("remove_data", removeData),
			zap.Bool("force", force))

		return docker.RunCleanup(rc, removeData, force)
	}),
}
