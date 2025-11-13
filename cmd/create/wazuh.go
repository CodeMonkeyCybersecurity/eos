// cmd/create/wazuh.go
// Configure Wazuh integration with external webhook (Iris)
//
// Created by Code Monkey Cybersecurity
// ABN: 77 177 673 061

package create

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

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
	"github.com/spf13/cobra"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

var (
	webhookOut  bool
	hookURL     string
	webhookPort string
	autoRestart bool
)

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

// TODO: refactor
type WazuhConfig struct {
	IntegrationsDir string
	OssecConfPath   string
	HookURL         string
	WebhookToken    string
	IntegrationName string
}

// TODO: refactor
func runCreateWazuh(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
	logger := otelzap.Ctx(rc.Ctx)

	if !webhookOut {
		return fmt.Errorf("use --webhook-out flag to configure webhook integration")
	}

	logger.Info("Starting Wazuh webhook integration setup")

	config := WazuhConfig{
		IntegrationsDir: "/var/ossec/integrations",
		OssecConfPath:   "/var/ossec/etc/ossec.conf",
		IntegrationName: "custom-iris",
	}

	// ASSESS - Check prerequisites
	logger.Info("Phase 1: ASSESS - Checking prerequisites")
	if err := checkWazuhInstalled(rc); err != nil {
		return fmt.Errorf("wazuh prerequisite check failed: %w", err)
	}

	// Get webhook URL
	if err := getWebhookURL(rc, &config); err != nil {
		return fmt.Errorf("failed to configure webhook URL: %w", err)
	}

	// Generate secure token
	if err := generateWebhookToken(rc, &config); err != nil {
		return fmt.Errorf("failed to generate webhook token: %w", err)
	}

	// INTERVENE - Install and configure
	logger.Info("Phase 2: INTERVENE - Installing integration")

	if err := installIntegrationScripts(rc, config); err != nil {
		return fmt.Errorf("failed to install integration scripts: %w", err)
	}

	if err := createEnvFile(rc, config); err != nil {
		return fmt.Errorf("failed to create .env file: %w", err)
	}

	if err := installPythonDependencies(rc); err != nil {
		return fmt.Errorf("failed to install Python dependencies: %w", err)
	}

	if err := updateOssecConf(rc, config); err != nil {
		return fmt.Errorf("failed to update ossec.conf: %w", err)
	}

	// EVALUATE - Test and restart
	logger.Info("Phase 3: EVALUATE - Testing integration")

	if err := testIntegration(rc, config); err != nil {
		logger.Warn("Integration test failed", zap.Error(err))
		logger.Warn("You may need to verify the webhook URL is accessible")
	}

	// Prompt for restart if not auto
	if !autoRestart {
		logger.Info("Restart required",
			zap.String("prompt", "Restart wazuh-manager now?"))
		if promptYesNo("Restart wazuh-manager now?") {
			autoRestart = true
		}
	}

	if autoRestart {
		logger.Info("Restarting wazuh-manager")
		if err := restartWazuhManager(rc); err != nil {
			return fmt.Errorf("failed to restart wazuh-manager: %w", err)
		}
		logger.Info("Wazuh manager restarted successfully")
	}

	printWazuhSuccessMessage(logger, config)

	return nil
}

// TODO: refactor
func checkWazuhInstalled(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	if _, err := os.Stat("/var/ossec"); os.IsNotExist(err) {
		return fmt.Errorf("Wazuh not found at /var/ossec. Is Wazuh installed?")
	}

	if _, err := os.Stat("/var/ossec/integrations"); os.IsNotExist(err) {
		return fmt.Errorf("Wazuh integrations directory not found")
	}

	// Check if wazuh-manager service exists
	cmd := exec.Command("systemctl", "status", "wazuh-manager")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("wazuh-manager service not found. Is Wazuh running?")
	}

	logger.Info("Wazuh installation verified",
		zap.String("path", "/var/ossec"),
		zap.String("integrations", "/var/ossec/integrations"),
		zap.String("service", "wazuh-manager"))

	return nil
}

// TODO: refactor
func getWebhookURL(rc *eos_io.RuntimeContext, config *WazuhConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	if hookURL != "" {
		config.HookURL = hookURL
		logger.Info("Using provided webhook URL", zap.String("url", config.HookURL))
		return nil
	}

	// Interactive prompt
	logger.Info("terminal prompt: Enter the Iris webhook URL")
	logger.Info("terminal prompt: Example: http://192.168.122.133:8080/webhook")

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("URL: ")

	url, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read input: %w", err)
	}

	config.HookURL = strings.TrimSpace(url)

	if config.HookURL == "" {
		return fmt.Errorf("webhook URL is required")
	}

	// Validate URL format
	if !strings.HasPrefix(config.HookURL, "http://") && !strings.HasPrefix(config.HookURL, "https://") {
		return fmt.Errorf("URL must start with http:// or https://")
	}

	logger.Info("Webhook URL configured", zap.String("url", config.HookURL))
	return nil
}

// TODO: refactor
func generateWebhookToken(rc *eos_io.RuntimeContext, config *WazuhConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Generate 32-byte random token
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return fmt.Errorf("failed to generate token: %w", err)
	}

	config.WebhookToken = hex.EncodeToString(tokenBytes)

	logger.Info("Generated secure authentication token",
		zap.String("token_preview", config.WebhookToken[:16]+"..."))

	return nil
}

// TODO: refactor
func installIntegrationScripts(rc *eos_io.RuntimeContext, config WazuhConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	shellScript := getCustomIrisShellScript()
	pythonScript := getCustomIrisPythonScript(shared.GetInternalHostname())

	shellPath := filepath.Join(config.IntegrationsDir, config.IntegrationName)
	pythonPath := filepath.Join(config.IntegrationsDir, config.IntegrationName+".py")

	// Write shell script
	if err := os.WriteFile(shellPath, []byte(shellScript), shared.SecretDirPerm); err != nil {
		return fmt.Errorf("failed to write shell script: %w", err)
	}

	// Write Python script
	if err := os.WriteFile(pythonPath, []byte(pythonScript), shared.SecureConfigFilePerm); err != nil {
		return fmt.Errorf("failed to write Python script: %w", err)
	}

	// Set ownership to root:wazuh
	chownCmd := exec.Command("chown", "root:wazuh", shellPath)
	if err := chownCmd.Run(); err != nil {
		logger.Warn("Could not set ownership on shell script",
			zap.String("path", shellPath),
			zap.Error(err))
	}

	chownCmd = exec.Command("chown", "root:wazuh", pythonPath)
	if err := chownCmd.Run(); err != nil {
		logger.Warn("Could not set ownership on Python script",
			zap.String("path", pythonPath),
			zap.Error(err))
	}

	logger.Info("Integration scripts installed",
		zap.String("shell_script", shellPath),
		zap.String("python_script", pythonPath),
		zap.String("shell_perms", "750"),
		zap.String("python_perms", "640"))

	return nil
}

// TODO: refactor
func createEnvFile(rc *eos_io.RuntimeContext, config WazuhConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	envPath := filepath.Join(config.IntegrationsDir, ".env")

	envContent := fmt.Sprintf(`# Iris Webhook Configuration
# Generated by eos create wazuh --webhook-out

HOOK_URL=%s
WEBHOOK_TOKEN=%s
`, config.HookURL, config.WebhookToken)

	if err := os.WriteFile(envPath, []byte(envContent), shared.SecureConfigFilePerm); err != nil {
		return fmt.Errorf("failed to write .env file: %w", err)
	}

	// Set ownership
	chownCmd := exec.Command("chown", "root:wazuh", envPath)
	if err := chownCmd.Run(); err != nil {
		logger.Warn("Could not set ownership on .env file",
			zap.String("path", envPath),
			zap.Error(err))
	}

	logger.Info("Environment configuration created",
		zap.String("path", envPath),
		zap.String("permissions", "640"))

	return nil
}

// TODO: refactor
func installPythonDependencies(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	pythonBin := "/var/ossec/framework/python/bin/pip3"

	if _, err := os.Stat(pythonBin); os.IsNotExist(err) {
		return fmt.Errorf("Wazuh Python not found at %s", pythonBin)
	}

	dependencies := []string{"requests", "python-dotenv"}

	for _, dep := range dependencies {
		logger.Debug("Installing Python dependency", zap.String("package", dep))

		cmd := exec.Command(pythonBin, "install", dep)
		output, err := cmd.CombinedOutput()

		if err != nil {
			// Check if already installed
			if strings.Contains(string(output), "Requirement already satisfied") {
				logger.Debug("Python dependency already installed", zap.String("package", dep))
				continue
			}
			return fmt.Errorf("failed to install %s: %w\n%s", dep, err, string(output))
		}

		logger.Info("Python dependency installed", zap.String("package", dep))
	}

	return nil
}

// TODO: refactor
func updateOssecConf(rc *eos_io.RuntimeContext, config WazuhConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	confPath := config.OssecConfPath

	// Backup first
	backupPath := fmt.Sprintf("%s.backup.%d", confPath, time.Now().Unix())
	if err := copyFile(confPath, backupPath); err != nil {
		return fmt.Errorf("failed to backup ossec.conf: %w", err)
	}
	logger.Info("Configuration backed up", zap.String("backup", backupPath))

	// Read current config
	data, err := os.ReadFile(confPath)
	if err != nil {
		return fmt.Errorf("failed to read ossec.conf: %w", err)
	}

	content := string(data)

	// Check if integration already exists
	if strings.Contains(content, "<name>"+config.IntegrationName+"</name>") {
		logger.Warn("Integration already exists in ossec.conf")
		logger.Info("terminal prompt: Replace existing integration?")

		if !promptYesNo("Replace existing integration?") {
			logger.Info("Skipping ossec.conf update")
			return nil
		}

		// Remove existing integration block
		content = removeExistingIntegration(content, config.IntegrationName)
	}

	// Add new integration block before last </ossec_config>
	integrationBlock := fmt.Sprintf(`
  <integration>
    <name>%s</name>
    <hook_url>%s</hook_url>
    <level>8</level>
    <alert_format>json</alert_format>
  </integration>

</ossec_config>`, config.IntegrationName, config.HookURL)

	// Replace the last </ossec_config> with our integration + closing tag
	content = strings.TrimSuffix(content, "</ossec_config>")
	content = strings.TrimSuffix(content, "\n")
	content += integrationBlock

	// Write updated config
	if err := os.WriteFile(confPath, []byte(content), shared.SecureConfigFilePerm); err != nil {
		return fmt.Errorf("failed to write ossec.conf: %w", err)
	}

	logger.Info("Integration added to ossec.conf",
		zap.String("integration", config.IntegrationName),
		zap.Int("alert_level", 8),
		zap.String("format", "json"))

	return nil
}

// TODO: refactor
func removeExistingIntegration(content, integrationName string) string {
	// Remove existing integration block using regex
	pattern := `(?s)<integration>\s*<name>` + regexp.QuoteMeta(integrationName) + `</name>.*?</integration>\s*`
	re := regexp.MustCompile(pattern)
	return re.ReplaceAllString(content, "")
}

// TODO: refactor
func testIntegration(rc *eos_io.RuntimeContext, config WazuhConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Test webhook connectivity first
	healthURL := strings.Replace(config.HookURL, "/webhook", "/health", 1)
	logger.Debug("Testing webhook connectivity", zap.String("url", healthURL))

	cmd := exec.Command("curl", "-s", "--connect-timeout", "3", healthURL)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("webhook not reachable: %w", err)
	}

	if strings.Contains(string(output), "healthy") || strings.Contains(string(output), "status") {
		logger.Info("Webhook connectivity verified", zap.String("url", healthURL))
	} else {
		return fmt.Errorf("unexpected response from webhook: %s", string(output))
	}

	// Create test alert
	testAlert := `{
  "timestamp": "` + time.Now().Format(time.RFC3339) + `",
  "rule": {"level": 10, "description": "Test alert from eos", "id": "999999"},
  "agent": {"id": "000", "name": "eos-test", "ip": "` + shared.GetInternalHostname() + `"},
  "manager": {"name": "test"},
  "data": {
    "vulnerability": {
      "severity": "High",
      "package": {"name": "test-package"},
      "title": "Test Alert from eos create wazuh"
    }
  }
}`

	testFile := "/tmp/eos_test_alert.json"
	if err := os.WriteFile(testFile, []byte(testAlert), shared.ConfigFilePerm); err != nil {
		return fmt.Errorf("failed to create test alert: %w", err)
	}
	defer func() { _ = os.Remove(testFile) }()

	// Test integration script
	integrationPath := filepath.Join(config.IntegrationsDir, config.IntegrationName)
	logger.Debug("Testing integration script", zap.String("path", integrationPath))

	cmd = exec.Command(integrationPath, testFile, "debug")
	output, err = cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("integration test failed: %w\n%s", err, string(output))
	}

	logger.Info("Integration test successful")

	return nil
}

// TODO: refactor
func restartWazuhManager(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	cmd := exec.Command("systemctl", "restart", "wazuh-manager")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to restart service: %w", err)
	}

	// Wait and verify
	time.Sleep(2 * time.Second)

	cmd = exec.Command("systemctl", "is-active", "wazuh-manager")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("wazuh-manager did not start properly")
	}

	logger.Info("Service restarted successfully", zap.String("service", "wazuh-manager"))

	return nil
}

// TODO: refactor
func printWazuhSuccessMessage(logger otelzap.LoggerWithCtx, config WazuhConfig) {
	logger.Info("Wazuh webhook integration configured successfully",
		zap.String("webhook_url", config.HookURL),
		zap.String("token_preview", config.WebhookToken[:16]+"..."),
		zap.Int("alert_level", 8),
		zap.String("integration", config.IntegrationName))

	logger.Info("Files created",
		zap.String("shell_script", filepath.Join(config.IntegrationsDir, config.IntegrationName)),
		zap.String("python_script", filepath.Join(config.IntegrationsDir, config.IntegrationName+".py")),
		zap.String("env_file", filepath.Join(config.IntegrationsDir, ".env")))

	logger.Info("Configuration updated",
		zap.String("file", config.OssecConfPath),
		zap.String("backup", "created"))

	if !autoRestart {
		logger.Info("Manual restart required",
			zap.String("command", "sudo systemctl restart wazuh-manager"))
	}

	logger.Info("Testing",
		zap.String("test_command", fmt.Sprintf("sudo %s/%s /tmp/eos_test_alert.json debug",
			config.IntegrationsDir, config.IntegrationName)),
		zap.String("logs", "sudo tail -f /var/ossec/logs/integrations.log"))

	logger.Info("Monitoring",
		zap.String("integration_logs", "sudo tail -f /var/ossec/logs/integrations.log"),
		zap.String("sent_payloads", "sudo tail -f /var/ossec/logs/sent_payload.log"),
		zap.String("alerts", "sudo tail -f /var/ossec/logs/alerts/alerts.json"))
}

// Helper functions
// TODO: refactor
func promptYesNo(prompt string) bool {
	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("%s [y/N]: ", prompt)
	response, _ := reader.ReadString('\n')
	response = strings.TrimSpace(strings.ToLower(response))
	return response == "y" || response == "yes"
}

// TODO: refactor
func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, shared.SecureConfigFilePerm)
}

// TODO: refactor
// Configuration flags moved to pkg/wazuh/config
var wazuhFlags = config.DefaultFlags()

func init() {
	CreateCmd.AddCommand(CreateWazuhCmd)
	CreateWazuhCmd.Flags().BoolVar(&wazuhFlags.IgnoreHardwareCheck, "ignore", false, "Ignore Wazuh hardware requirements check")
	CreateWazuhCmd.Flags().BoolVar(&wazuhFlags.OverwriteInstall, "overwrite", false, "Overwrite existing Wazuh installation")

	// Add mapping command
	CreateCmd.AddCommand(mappingCmd)
}

// TODO: refactor
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

// TODO: refactor
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
