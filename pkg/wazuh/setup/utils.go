// pkg/wazuh/setup/utils.go
// Utility functions for Wazuh integration setup
//
// Created by Code Monkey Cybersecurity
// ABN: 77 177 673 061

package setup

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// PromptYesNo prompts the user for a yes/no response
func PromptYesNo(prompt string) bool {
	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("%s [y/N]: ", prompt)
	response, _ := reader.ReadString('\n')
	response = strings.TrimSpace(strings.ToLower(response))
	return response == "y" || response == "yes"
}

// CopyFile copies a file from src to dst
func CopyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, shared.SecureConfigFilePerm)
}

// PrintWazuhSuccessMessage prints the success message with configuration details
func PrintWazuhSuccessMessage(logger otelzap.LoggerWithCtx, config *Config) {
	logger.Info("Wazuh webhook integration configured successfully",
		zap.String("webhook_url", config.HookURL),
		zap.String("token_preview", config.WebhookToken[:16]+"..."),
		zap.Int("alert_level", 8),
		zap.String("integration", config.IntegrationName))

	logger.Info("Files created",
		zap.String("shell_script", config.IntegrationsDir+"/"+config.IntegrationName),
		zap.String("python_script", config.IntegrationsDir+"/"+config.IntegrationName+".py"),
		zap.String("env_file", config.IntegrationsDir+"/.env"))

	logger.Info("Configuration updated",
		zap.String("file", config.OssecConfPath),
		zap.String("backup", "created"))

	if !config.AutoRestart {
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
