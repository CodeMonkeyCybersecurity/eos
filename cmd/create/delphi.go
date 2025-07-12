package create

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/delphi/agents"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/delphi/config"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/delphi/credentials"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/delphi/docker"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_unix"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/privilege_check"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/utils"
)

// Configuration flags moved to pkg/delphi/config
var delphiFlags = config.DefaultFlags()

func init() {
	CreateCmd.AddCommand(CreateDelphiCmd)
	CreateDelphiCmd.Flags().BoolVar(&delphiFlags.IgnoreHardwareCheck, "ignore", false, "Ignore Wazuh hardware requirements check")
	CreateDelphiCmd.Flags().BoolVar(&delphiFlags.OverwriteInstall, "overwrite", false, "Overwrite existing Wazuh installation")

	// Add mapping command
	CreateCmd.AddCommand(mappingCmd)
}

var CreateDelphiCmd = &cobra.Command{
	Use:     "delphi",
	Aliases: []string{"wazuh"},
	Short:   "Deploy Delphi (Wazuh all-in-one) with optional hardware check override",
	Long: `Deploy Delphi (Wazuh all-in-one) security monitoring platform.

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
  eos create delphi

  # Install ignoring hardware requirements
  eos create delphi --ignore

  # Install with overwrite of existing installation
  eos create delphi --overwrite

  # Install with both options
  eos create delphi --ignore --overwrite`,
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		log := otelzap.Ctx(rc.Ctx)

		if err := platform.RequireLinuxDistro(rc, []string{"debian", "rhel"}); err != nil {
			log.Fatal("Unsupported Linux distro", zap.Error(err))
		}

		tmpDir := "/tmp"
		scriptURL := "https://packages.wazuh.com/4.11/wazuh-install.sh"
		scriptPath := filepath.Join(tmpDir, "wazuh-install.sh")

		log.Info("Downloading Wazuh installer", zap.String("url", scriptURL))
		if err := utils.DownloadFile(scriptPath, scriptURL); err != nil {
			return fmt.Errorf("failed to download installer: %w", err)
		}
		if err := os.Chmod(scriptPath, shared.DirPermStandard); err != nil {
			return fmt.Errorf("failed to make script executable: %w", err)
		}

		args = []string{"-a"}
		if delphiFlags.IgnoreHardwareCheck {
			log.Info("Ignoring hardware checks (passing -i)")
			args = append(args, "-i")
		}
		if delphiFlags.OverwriteInstall {
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

		log.Info("Delphi (Wazuh) setup complete")
		log.Info("To access the Wazuh Dashboard:")
		log.Info("Run this on your **local machine** (not over SSH):")
		log.Info("    firefox https://$(hostname -I | awk '{print $1}')")
		log.Info("Or forward port with:")
		log.Info("    ssh -L 8443:localhost:443 user@your-server")
		log.Info("Then browse: https://localhost:8443")
		log.Info("To harden this install, run: `eos harden delphi`")

		return nil
	}),
}

// extractWazuhPasswords moved to pkg/delphi/credentials
// DEPRECATED: Use credentials.ExtractWazuhPasswords instead
func extractWazuhPasswords(rc *eos_io.RuntimeContext) error {
	searchPaths := []string{"/root", "/tmp", "/opt", "/var/tmp", "."}
	for _, dir := range searchPaths {
		tarPath := filepath.Join(dir, "wazuh-install-files.tar")
		if eos_unix.Exists(tarPath) {
			otelzap.Ctx(rc.Ctx).Info(" Found Wazuh tar file", zap.String("path", tarPath))
			cmd := exec.Command("tar", "-O", "-xvf", tarPath, "wazuh-install-files/wazuh-passwords.txt")
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			if err := cmd.Run(); err != nil {
				return fmt.Errorf("failed to extract passwords: %w", err)
			}
			return nil
		}
	}
	return fmt.Errorf("wazuh-install-files.tar not found in expected paths")
}

var mappingCmd = &cobra.Command{
	Use:   "mapping",
	Short: "Suggest the best agent package for each endpoint",
	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		return agents.RunMapping(rc)
	}),
}

// DeployCmd is the root command for Wazuh deployment operations
var DeployCmd = &cobra.Command{
	Use:     "deploy",
	Aliases: []string{"install"},
	Short:   "Deploy Wazuh/Delphi with Docker containers",
	Long: `Deploy Wazuh/Delphi using Docker containers with enhanced configuration.

This command provides comprehensive Wazuh deployment functionality including:
- Single-node and multi-node deployment options
- Automatic certificate generation
- Port configuration for Hecate compatibility
- Custom credential setup with secure password hashing

Examples:
  eos delphi deploy docker                    # Interactive Docker deployment
  eos delphi deploy docker --single-node     # Single-node deployment
  eos delphi deploy docker --multi-node      # Multi-node deployment
  eos delphi deploy credentials              # Change default credentials`,

	RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
		otelzap.Ctx(rc.Ctx).Info("No subcommand provided for deploy command")
		_ = cmd.Help()
		return nil
	}),
}

func init() {
	// Add subcommands
	DeployCmd.AddCommand(dockerDeployCmd)
	DeployCmd.AddCommand(delphiCredentialsCmd)
	DeployCmd.AddCommand(cleanupCmd)

	// Set up flags for dockerDeployCmd
	dockerDeployCmd.Flags().StringP("version", "v", "", "Wazuh version to deploy (e.g., 4.10.1)")
	dockerDeployCmd.Flags().Bool("single-node", false, "Deploy as single-node")
	dockerDeployCmd.Flags().Bool("multi-node", false, "Deploy as multi-node")
	dockerDeployCmd.Flags().String("proxy", "", "Proxy address for certificate generation")
	dockerDeployCmd.Flags().IntP("port", "p", 8011, "External port for Wazuh dashboard")
	dockerDeployCmd.Flags().BoolP("force", "f", false, "Force deployment without prompts")

	// Set up flags for delphiCredentialsCmd
	delphiCredentialsCmd.Flags().String("admin-password", "", "New admin password")
	delphiCredentialsCmd.Flags().String("kibana-password", "", "New Kibana dashboard password")
	delphiCredentialsCmd.Flags().String("api-password", "", "New API password")
	delphiCredentialsCmd.Flags().String("deploy-type", "", "Deployment type (single-node or multi-node)")
	delphiCredentialsCmd.Flags().BoolP("interactive", "i", false, "Interactive mode with prompts")

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
  eos create delphi deploy docker --version 4.10.1 --single-node
  eos create delphi deploy docker --version 4.10.1 --multi-node --proxy proxy.example.com
  eos create delphi deploy docker --version 4.10.1 --port 8011`,

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

// delphiCredentialsCmd changes default Wazuh credentials
var delphiCredentialsCmd = &cobra.Command{
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
  eos create delphi deploy credentials --interactive
  eos create delphi deploy credentials --admin-password "newpass" --deploy-type single-node`,

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
  eos create delphi deploy cleanup                   # Remove deployment, keep data
  eos create delphi deploy cleanup --remove-data    # Remove deployment and data
  eos create delphi deploy cleanup --force          # Skip confirmation`,

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
