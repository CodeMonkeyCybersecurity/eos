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

type WazuhConfig struct {
	IntegrationsDir string
	OssecConfPath   string
	HookURL         string
	WebhookToken    string
	IntegrationName string
}

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

func installIntegrationScripts(rc *eos_io.RuntimeContext, config WazuhConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	shellScript := getCustomIrisShellScript()
	pythonScript := getCustomIrisPythonScript()

	shellPath := filepath.Join(config.IntegrationsDir, config.IntegrationName)
	pythonPath := filepath.Join(config.IntegrationsDir, config.IntegrationName+".py")

	// Write shell script
	if err := os.WriteFile(shellPath, []byte(shellScript), 0750); err != nil {
		return fmt.Errorf("failed to write shell script: %w", err)
	}

	// Write Python script
	if err := os.WriteFile(pythonPath, []byte(pythonScript), 0640); err != nil {
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

func createEnvFile(rc *eos_io.RuntimeContext, config WazuhConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	envPath := filepath.Join(config.IntegrationsDir, ".env")

	envContent := fmt.Sprintf(`# Iris Webhook Configuration
# Generated by eos create wazuh --webhook-out

HOOK_URL=%s
WEBHOOK_TOKEN=%s
`, config.HookURL, config.WebhookToken)

	if err := os.WriteFile(envPath, []byte(envContent), 0640); err != nil {
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
	if err := os.WriteFile(confPath, []byte(content), 0640); err != nil {
		return fmt.Errorf("failed to write ossec.conf: %w", err)
	}

	logger.Info("Integration added to ossec.conf",
		zap.String("integration", config.IntegrationName),
		zap.Int("alert_level", 8),
		zap.String("format", "json"))

	return nil
}

func removeExistingIntegration(content, integrationName string) string {
	// Remove existing integration block using regex
	pattern := `(?s)<integration>\s*<name>` + regexp.QuoteMeta(integrationName) + `</name>.*?</integration>\s*`
	re := regexp.MustCompile(pattern)
	return re.ReplaceAllString(content, "")
}

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
  "agent": {"id": "000", "name": "eos-test", "ip": "127.0.0.1"},
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
	if err := os.WriteFile(testFile, []byte(testAlert), 0644); err != nil {
		return fmt.Errorf("failed to create test alert: %w", err)
	}
	defer os.Remove(testFile)

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

func promptYesNo(prompt string) bool {
	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("%s [y/N]: ", prompt)
	response, _ := reader.ReadString('\n')
	response = strings.TrimSpace(strings.ToLower(response))
	return response == "y" || response == "yes"
}

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0640)
}
