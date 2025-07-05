package deploy

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/privilege_check"
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

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
	DeployCmd.AddCommand(newDockerDeployCmd())
	DeployCmd.AddCommand(newCredentialsCmd())
	DeployCmd.AddCommand(newCleanupCmd())
}

// newDockerDeployCmd creates the Docker deployment command
func newDockerDeployCmd() *cobra.Command {
	var (
		version      string
		singleNode   bool
		multiNode    bool
		proxyAddress string
		port         int
		force        bool
	)

	cmd := &cobra.Command{
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
  eos delphi deploy docker --version 4.10.1 --single-node
  eos delphi deploy docker --version 4.10.1 --multi-node --proxy proxy.example.com
  eos delphi deploy docker --version 4.10.1 --port 8011`,

		RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
			logger := otelzap.Ctx(rc.Ctx)

			// Check privileges
			privilegeManager := privilege_check.NewPrivilegeManager(nil)
			if err := privilegeManager.CheckSudoOnly(rc); err != nil {
				logger.Error("Root privileges required for Docker deployment", zap.Error(err))
				return err
			}

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

			return runDockerDeployment(rc, version, deployType, proxyAddress, port, force)
		}),
	}

	cmd.Flags().StringVarP(&version, "version", "v", "", "Wazuh version to deploy (e.g., 4.10.1)")
	cmd.Flags().BoolVar(&singleNode, "single-node", false, "Deploy as single-node")
	cmd.Flags().BoolVar(&multiNode, "multi-node", false, "Deploy as multi-node")
	cmd.Flags().StringVar(&proxyAddress, "proxy", "", "Proxy address for certificate generation")
	cmd.Flags().IntVarP(&port, "port", "p", 8011, "External port for Wazuh dashboard")
	cmd.Flags().BoolVarP(&force, "force", "f", false, "Force deployment without prompts")

	return cmd
}

// newCredentialsCmd creates the credentials management command
func newCredentialsCmd() *cobra.Command {
	var (
		adminPassword    string
		kibanaPassword   string
		apiPassword      string
		deployType       string
		interactive      bool
	)

	cmd := &cobra.Command{
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
  eos delphi deploy credentials --interactive
  eos delphi deploy credentials --admin-password "newpass" --deploy-type single-node`,

		RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
			logger := otelzap.Ctx(rc.Ctx)

			logger.Info("Changing Wazuh credentials", 
				zap.String("deploy_type", deployType),
				zap.Bool("interactive", interactive))

			return runCredentialsChange(rc, adminPassword, kibanaPassword, apiPassword, deployType, interactive)
		}),
	}

	cmd.Flags().StringVar(&adminPassword, "admin-password", "", "New admin password")
	cmd.Flags().StringVar(&kibanaPassword, "kibana-password", "", "New Kibana dashboard password")
	cmd.Flags().StringVar(&apiPassword, "api-password", "", "New API password")
	cmd.Flags().StringVar(&deployType, "deploy-type", "", "Deployment type (single-node or multi-node)")
	cmd.Flags().BoolVarP(&interactive, "interactive", "i", false, "Interactive mode with prompts")

	return cmd
}

// newCleanupCmd creates the cleanup/removal command
func newCleanupCmd() *cobra.Command {
	var (
		force      bool
		removeData bool
	)

	cmd := &cobra.Command{
		Use:     "cleanup",
		Aliases: []string{"remove", "uninstall"},
		Short:   "Remove Wazuh Docker deployment",
		Long: `Remove Wazuh Docker deployment and optionally clean up data.

This command safely removes the Wazuh Docker deployment:
- Stops all containers
- Removes containers and networks
- Optionally removes volumes and data

Examples:
  eos delphi deploy cleanup                   # Remove deployment, keep data
  eos delphi deploy cleanup --remove-data    # Remove deployment and data
  eos delphi deploy cleanup --force          # Skip confirmation`,

		RunE: eos.Wrap(func(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
			logger := otelzap.Ctx(rc.Ctx)

			logger.Info("Cleaning up Wazuh deployment", 
				zap.Bool("remove_data", removeData),
				zap.Bool("force", force))

			return runCleanup(rc, removeData, force)
		}),
	}

	cmd.Flags().BoolVarP(&force, "force", "f", false, "Skip confirmation prompts")
	cmd.Flags().BoolVar(&removeData, "remove-data", false, "Remove volumes and persistent data")

	return cmd
}

// Implementation functions

func runDockerDeployment(rc *eos_io.RuntimeContext, version, deployType, proxyAddress string, port int, force bool) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Interactive prompts if not provided
	if version == "" {
		fmt.Print("Enter Wazuh version (e.g., 4.10.1): ")
		fmt.Scanln(&version)
	}

	if deployType == "" {
		fmt.Print("Deployment type (1 for single-node, 2 for multi-node): ")
		var choice string
		fmt.Scanln(&choice)
		switch choice {
		case "1":
			deployType = "single-node"
		case "2":
			deployType = "multi-node"
		default:
			return fmt.Errorf("invalid deployment type choice")
		}
	}

	if proxyAddress == "" {
		fmt.Print("Enter proxy address (or press Enter to skip): ")
		fmt.Scanln(&proxyAddress)
	}

	logger.Info("Starting deployment process",
		zap.String("version", version),
		zap.String("deploy_type", deployType),
		zap.String("proxy", proxyAddress),
		zap.Int("port", port))

	// Change to /opt directory
	if err := os.Chdir("/opt"); err != nil {
		return fmt.Errorf("failed to change to /opt directory: %w", err)
	}

	// Clean up any existing installation
	if !force {
		fmt.Print("Remove any existing Wazuh installation? [Y/n]: ")
		var response string
		fmt.Scanln(&response)
		if response != "n" && response != "N" {
			logger.Info("Removing existing wazuh-docker directory")
			exec.Command("rm", "-rf", "wazuh-docker").Run()
		}
	} else {
		exec.Command("rm", "-rf", "wazuh-docker").Run()
	}

	// Set vm.max_map_count for Elasticsearch
	logger.Info("Setting vm.max_map_count for Elasticsearch")
	if err := exec.Command("sysctl", "-w", "vm.max_map_count=262144").Run(); err != nil {
		logger.Warn("Failed to set vm.max_map_count", zap.Error(err))
	}

	// Clone Wazuh repository
	logger.Info("Cloning Wazuh Docker repository", zap.String("version", version))
	cloneCmd := exec.Command("git", "clone", "https://github.com/wazuh/wazuh-docker.git", "-b", "v"+version)
	if err := cloneCmd.Run(); err != nil {
		return fmt.Errorf("failed to clone Wazuh repository: %w", err)
	}

	// Change to deployment directory
	deployDir := filepath.Join("wazuh-docker", deployType)
	if err := os.Chdir(deployDir); err != nil {
		return fmt.Errorf("failed to change to deployment directory: %w", err)
	}

	// Configure proxy if provided
	if proxyAddress != "" {
		logger.Info("Configuring proxy for certificate generation", zap.String("proxy", proxyAddress))
		if err := configureProxy(proxyAddress); err != nil {
			logger.Warn("Failed to configure proxy", zap.Error(err))
		}
	}

	// Generate certificates
	logger.Info("Generating indexer certificates")
	certCmd := exec.Command("docker", "compose", "-f", "generate-indexer-certs.yml", "run", "--rm", "generator")
	if err := certCmd.Run(); err != nil {
		return fmt.Errorf("failed to generate certificates: %w", err)
	}

	// Configure port mapping
	if port != 443 {
		logger.Info("Configuring port mapping for Hecate compatibility", zap.Int("port", port))
		if err := configurePortMapping(port); err != nil {
			logger.Warn("Failed to configure port mapping", zap.Error(err))
		}
	}

	// Start containers
	logger.Info("Starting Wazuh containers")
	startCmd := exec.Command("docker", "compose", "up", "-d")
	if err := startCmd.Run(); err != nil {
		return fmt.Errorf("failed to start containers: %w", err)
	}

	// Set file permissions
	if err := exec.Command("chmod", "660", "*.conf").Run(); err != nil {
		logger.Warn("Failed to set file permissions", zap.Error(err))
	}

	logger.Info("Wazuh deployment completed successfully")
	return nil
}

func configureProxy(proxyAddress string) error {
	// Add proxy configuration to generate-indexer-certs.yml
	proxyConfig := fmt.Sprintf(`
    environment:
      - HTTP_PROXY=%s`, proxyAddress)

	file, err := os.OpenFile("generate-indexer-certs.yml", os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.WriteString(proxyConfig)
	return err
}

func configurePortMapping(port int) error {
	// Read docker-compose.yml
	content, err := os.ReadFile("docker-compose.yml")
	if err != nil {
		return err
	}

	// Replace port mapping
	oldMapping := "- 443:5601"
	newMapping := fmt.Sprintf("- %d:5601", port)
	
	newContent := strings.ReplaceAll(string(content), oldMapping, newMapping)

	// Write back to file
	return os.WriteFile("docker-compose.yml", []byte(newContent), 0644)
}

func runCredentialsChange(rc *eos_io.RuntimeContext, adminPassword, kibanaPassword, apiPassword, deployType string, interactive bool) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Interactive mode
	if interactive {
		if deployType == "" {
			fmt.Print("Deployment type (single-node or multi-node): ")
			fmt.Scanln(&deployType)
		}

		if adminPassword == "" {
			fmt.Print("Enter new admin password: ")
			fmt.Scanln(&adminPassword)
		}

		if kibanaPassword == "" {
			fmt.Print("Enter new Kibana password: ")
			fmt.Scanln(&kibanaPassword)
		}

		if apiPassword == "" {
			fmt.Print("Enter new API password: ")
			fmt.Scanln(&apiPassword)
		}
	}

	// Validate inputs
	if deployType == "" || adminPassword == "" || kibanaPassword == "" || apiPassword == "" {
		return fmt.Errorf("all parameters required: deploy-type, admin-password, kibana-password, api-password")
	}

	logger.Info("Updating Wazuh credentials", zap.String("deploy_type", deployType))

	// Change to deployment directory
	deployDir := filepath.Join("/opt/wazuh-docker", deployType)
	if err := os.Chdir(deployDir); err != nil {
		return fmt.Errorf("failed to change to deployment directory: %w", err)
	}

	// Stop containers
	logger.Info("Stopping containers for credential update")
	if err := exec.Command("docker", "compose", "down").Run(); err != nil {
		logger.Warn("Failed to stop containers", zap.Error(err))
	}

	// Update admin password
	if err := updateAdminPassword(adminPassword); err != nil {
		return fmt.Errorf("failed to update admin password: %w", err)
	}

	// Update Kibana password  
	if err := updateKibanaPassword(kibanaPassword); err != nil {
		return fmt.Errorf("failed to update Kibana password: %w", err)
	}

	// Update API password
	if err := updateAPIPassword(apiPassword); err != nil {
		return fmt.Errorf("failed to update API password: %w", err)
	}

	// Restart containers
	logger.Info("Restarting containers with new credentials")
	if err := exec.Command("docker", "compose", "up", "-d").Run(); err != nil {
		return fmt.Errorf("failed to restart containers: %w", err)
	}

	logger.Info("Credentials updated successfully")
	return nil
}

func updateAdminPassword(password string) error {
	// Update docker-compose.yml
	if err := updateComposeFile("INDEXER_PASSWORD=SecretPassword", fmt.Sprintf("INDEXER_PASSWORD=%s", password)); err != nil {
		return err
	}

	// Generate hash and update internal_users.yml
	hash, err := generatePasswordHash(password)
	if err != nil {
		return err
	}

	return updateInternalUsers("$2y$12$K/SpwjtB.wOHJ/Nc6GVRDuc1h0rM1DfvziFRNPtk27P.c4yDr9njO", hash)
}

func updateKibanaPassword(password string) error {
	// Update docker-compose.yml
	if err := updateComposeFile("DASHBOARD_PASSWORD=kibanaserver", fmt.Sprintf("DASHBOARD_PASSWORD=%s", password)); err != nil {
		return err
	}

	// Generate hash and update internal_users.yml
	hash, err := generatePasswordHash(password)
	if err != nil {
		return err
	}

	return updateInternalUsers("$2a$12$4AcgAt3xwOWadA5s5blL6ev39OXDNhmOesEoo33eZtrq2N0YrU3H.", hash)
}

func updateAPIPassword(password string) error {
	// Update docker-compose.yml
	if err := updateComposeFile("API_PASSWORD=MyS3cr37P450r.*-", fmt.Sprintf("API_PASSWORD=%s", password)); err != nil {
		return err
	}

	// Update wazuh.yml
	return updateWazuhYML("API_PASSWORD=MyS3cr37P450r.*-", fmt.Sprintf("API_PASSWORD=%s", password))
}

func updateComposeFile(oldValue, newValue string) error {
	return replaceInFile("docker-compose.yml", oldValue, newValue)
}

func updateInternalUsers(oldHash, newHash string) error {
	return replaceInFile("config/wazuh_indexer/internal_users.yml", oldHash, newHash)
}

func updateWazuhYML(oldValue, newValue string) error {
	return replaceInFile("config/wazuh_dashboard/wazuh.yml", oldValue, newValue)
}

func replaceInFile(filename, oldValue, newValue string) error {
	content, err := os.ReadFile(filename)
	if err != nil {
		return err
	}

	newContent := strings.ReplaceAll(string(content), oldValue, newValue)
	return os.WriteFile(filename, []byte(newContent), 0644)
}

func generatePasswordHash(password string) (string, error) {
	// Use Docker to generate hash
	cmd := exec.Command("docker", "run", "--rm", "-i", "wazuh/wazuh-indexer:latest", 
		"bash", "/usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh")
	cmd.Stdin = strings.NewReader(password + "\n" + password + "\n")
	
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	// Parse hash from output
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "$") {
			return strings.TrimSpace(line), nil
		}
	}

	return "", fmt.Errorf("failed to extract hash from output")
}

func runCleanup(rc *eos_io.RuntimeContext, removeData, force bool) error {
	logger := otelzap.Ctx(rc.Ctx)

	if !force {
		fmt.Print("Are you sure you want to remove the Wazuh deployment? [y/N]: ")
		var response string
		fmt.Scanln(&response)
		if response != "y" && response != "Y" {
			logger.Info("Cleanup cancelled")
			return nil
		}
	}

	// Change to /opt directory
	if err := os.Chdir("/opt"); err != nil {
		return fmt.Errorf("failed to change to /opt directory: %w", err)
	}

	// Stop and remove containers
	for _, deployType := range []string{"multi-node", "single-node"} {
		deployDir := filepath.Join("wazuh-docker", deployType)
		if _, err := os.Stat(deployDir); err == nil {
			logger.Info("Stopping containers", zap.String("deploy_type", deployType))
			
			oldDir, _ := os.Getwd()
			os.Chdir(deployDir)
			
			if removeData {
				exec.Command("docker", "compose", "down", "-v").Run()
			} else {
				exec.Command("docker", "compose", "down").Run()
			}
			
			os.Chdir(oldDir)
		}
	}

	// Show remaining containers
	logger.Info("Checking remaining containers")
	cmd := exec.Command("docker", "ps")
	cmd.Stdout = os.Stdout
	cmd.Run()

	fmt.Print("Press Enter to continue with cleanup...")
	bufio.NewReader(os.Stdin).ReadBytes('\n')

	// Remove wazuh-docker directory
	logger.Info("Removing wazuh-docker directory")
	if err := exec.Command("rm", "-rf", "wazuh-docker").Run(); err != nil {
		logger.Error("Failed to remove wazuh-docker directory", zap.Error(err))
		return err
	}

	logger.Info("Cleanup completed successfully")
	return nil
}