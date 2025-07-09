package create

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/delphi"
	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_cli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_unix"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/platform"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/privilege_check"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/utils"
)

var ignoreHardwareCheck bool
var overwriteInstall bool

func init() {
	CreateCmd.AddCommand(CreateDelphiCmd)
	CreateDelphiCmd.Flags().BoolVar(&ignoreHardwareCheck, "ignore", false, "Ignore Wazuh hardware requirements check")
	CreateDelphiCmd.Flags().BoolVar(&overwriteInstall, "overwrite", false, "Overwrite existing Wazuh installation")

	// Add mapping command
	CreateCmd.AddCommand(mappingCmd)
}

var CreateDelphiCmd = &cobra.Command{
	Use:     "delphi",
	Aliases: []string{"wazuh"},
	Short:   "Deploy Delphi (Wazuh all-in-one) with optional hardware check override",
	Long: `Installs the full Wazuh stack (server, dashboard, and indexer) using the official quickstart script.
By default, this checks your system's hardware (4GB RAM, 2+ cores). Use --ignore to bypass this check.`,
	RunE: eos.Wrap(runDelphiInstall),
}

func runDelphiInstall(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	log := otelzap.Ctx(rc.Ctx)

	if err := platform.RequireLinuxDistro(rc, []string{"debian", "rhel"}); err != nil {
		log.Fatal("Unsupported Linux distro", zap.Error(err))
	}

	tmpDir := "/tmp"
	scriptURL := "https://packages.wazuh.com/4.11/wazuh-install.sh"
	scriptPath := filepath.Join(tmpDir, "wazuh-install.sh")

	log.Info(" Downloading Wazuh installer", zap.String("url", scriptURL))
	if err := utils.DownloadFile(scriptPath, scriptURL); err != nil {
		return fmt.Errorf("failed to download installer: %w", err)
	}
	if err := os.Chmod(scriptPath, shared.DirPermStandard); err != nil {
		return fmt.Errorf("failed to make script executable: %w", err)
	}

	args = []string{"-a"}
	if ignoreHardwareCheck {
		log.Info(" Ignoring hardware checks (passing -i)")
		args = append(args, "-i")
	}
	if overwriteInstall {
		log.Info(" Overwriting existing installation (passing -o)")
		args = append(args, "-o")
	}

	log.Info(" Running Wazuh installer script")
	cmdArgs := append([]string{scriptPath}, args...)
	installCmd := exec.Command("bash", cmdArgs...)
	installCmd.Stdout = os.Stdout
	installCmd.Stderr = os.Stderr
	if err := installCmd.Run(); err != nil {
		return fmt.Errorf("installation failed: %w", err)
	}
	log.Info(" Wazuh installation completed")

	log.Info(" Attempting to extract Wazuh admin credentials")
	if err := extractWazuhPasswords(rc); err != nil {
		log.Warn("Could not extract Wazuh credentials", zap.Error(err))
	}

	log.Info(" Disabling Wazuh repo updates")
	distro := platform.DetectLinuxDistro(rc)
	switch distro {
	case "debian", "ubuntu":
		cmd := exec.Command("sed", "-i", "s/^deb /#deb /", "/etc/apt/sources.list.d/wazuh.list")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			log.Warn("Failed to comment out Wazuh APT repo", zap.Error(err))
		} else {
			log.Info(" Wazuh APT repo commented out")
			_ = exec.Command("apt", "update").Run()
		}
	default:
		cmd := exec.Command("sed", "-i", "s/^enabled=1/enabled=0/", "/etc/yum.repos.d/wazuh.repo")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			log.Warn("Failed to disable Wazuh yum repo", zap.Error(err))
		} else {
			log.Info(" Wazuh yum repo disabled")
		}
	}

	log.Info(" Delphi (Wazuh) setup complete")
	log.Info("To access the Wazuh Dashboard:")
	log.Info(" Run this on your **local machine** (not over SSH):")
	log.Info("    firefox https://$(hostname -I | awk '{print $1}')")
	log.Info("Or forward port with:")
	log.Info("    ssh -L 8443:localhost:443 user@your-server")
	log.Info("Then browse: https://localhost:8443")
	log.Info(" To harden this install, run: `eos harden delphi`")

	return nil
}

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
		runMapping(rc)
		return nil
	}),
}

type OSInfo struct {
	Name         string `json:"name"`
	Version      string `json:"version"`
	Architecture string `json:"architecture"`
}

type Agent struct {
	ID      string `json:"id"`
	Version string `json:"version"`
	OS      OSInfo `json:"os"`
}

type AgentsResponse struct {
	Data struct {
		AffectedItems []Agent `json:"affected_items"`
	} `json:"data"`
	Error   int    `json:"error"`
	Message string `json:"message"`
}

type PackageMapping struct {
	Distribution string
	MinVersion   int
	Arch         string
	Package      string
}

func runMapping(rc *eos_io.RuntimeContext) {
	cfg, err := delphi.ResolveConfig(rc)
	if err != nil {
		otelzap.Ctx(rc.Ctx).Fatal("Failed to resolve Delphi config", zap.Error(err))
	}

	baseURL := fmt.Sprintf("%s://%s:%s", defaultStr(cfg.Protocol, "https"), cfg.FQDN, defaultStr(cfg.Port, "55000"))
	token, err := delphi.Authenticate(rc, cfg)
	if err != nil {
		otelzap.Ctx(rc.Ctx).Fatal("Authentication failed", zap.Error(err))
	}

	resp, err := fetchAgents(rc, baseURL, token)
	if err != nil {
		otelzap.Ctx(rc.Ctx).Fatal("Failed to fetch agents", zap.Error(err))
	}

	for _, agent := range resp.Data.AffectedItems {
		printAgentInfo(agent)

		mappings := getMappings(agent.OS.Name)
		if mappings == nil {
			fmt.Printf("   No mapping for distribution: %s\n", agent.OS.Name)
			continue
		}

		major, err := getMajorVersion(agent.OS.Version)
		if err != nil {
			fmt.Printf("   Could not parse version: %v\n", err)
			continue
		}

		pkg := matchPackage(mappings, strings.ToLower(agent.OS.Architecture), major)
		if pkg == "" {
			fmt.Printf("   No suitable package for version %s (%s)\n", agent.OS.Version, agent.OS.Architecture)
		} else {
			fmt.Printf("   Recommended package: %s\n", pkg)
		}
	}
}

func fetchAgents(rc *eos_io.RuntimeContext, baseURL, token string) (*AgentsResponse, error) {
	url := strings.TrimRight(baseURL, "/") + "/agents?select=id,os,version"
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: getAgentFetchTLSConfig()}}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP error: %w", err)
	}
	defer shared.SafeClose(rc.Ctx, resp.Body)

	var parsed AgentsResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("decode error: %w", err)
	}
	return &parsed, nil
}

func printAgentInfo(agent Agent) {
	fmt.Printf("\n Agent %s:\n", agent.ID)
	fmt.Printf("  OS: %s %s (%s)\n", agent.OS.Name, agent.OS.Version, agent.OS.Architecture)
}

func matchPackage(mappings []PackageMapping, arch string, major int) string {
	for _, m := range mappings {
		if m.Arch == arch && major >= m.MinVersion {
			return m.Package
		}
	}
	return ""
}

func defaultStr(val, fallback string) string {
	if val == "" {
		return fallback
	}
	return val
}

// getAgentFetchTLSConfig returns TLS configuration with proper security settings for agent fetching
func getAgentFetchTLSConfig() *tls.Config {
	// Allow insecure TLS only in development/testing environments
	if os.Getenv("Eos_INSECURE_TLS") == "true" || os.Getenv("GO_ENV") == "test" {
		return &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		}
	}

	// Secure TLS configuration for production agent fetching
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		},
		PreferServerCipherSuites: true,
	}
}

func getMappings(distribution string) []PackageMapping {
	switch strings.ToLower(distribution) {
	case "centos":
		return []PackageMapping{
			{"centos", 7, "x86_64", "wazuh-agent-4.11.0-1.x86_64.rpm"},
			{"centos", 7, "i386", "wazuh-agent-4.11.0-1.i386.rpm"},
			{"centos", 7, "aarch64", "wazuh-agent-4.11.0-1.aarch64.rpm"},
			{"centos", 7, "armhf", "wazuh-agent-4.11.0-1.armv7hl.rpm"},
		}
	case "debian":
		return []PackageMapping{
			{"debian", 8, "amd64", "wazuh-agent_4.11.0-1_amd64.deb"},
			{"debian", 8, "i386", "wazuh-agent_4.11.0-1_i386.deb"},
		}
	case "ubuntu":
		return []PackageMapping{
			{"ubuntu", 13, "amd64", "wazuh-agent_4.11.0-1_amd64.deb"},
			{"ubuntu", 13, "i386", "wazuh-agent_4.11.0-1_i386.deb"},
		}
	default:
		return nil
	}
}

func getMajorVersion(versionStr string) (int, error) {
	parts := strings.Split(versionStr, ".")
	return strconv.Atoi(parts[0])
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

		return runDockerDeployment(rc, version, deployType, proxyAddress, port, force)
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

		return runCredentialsChange(rc, adminPassword, kibanaPassword, apiPassword, deployType, interactive)
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

		return runCleanup(rc, removeData, force)
	}),
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
