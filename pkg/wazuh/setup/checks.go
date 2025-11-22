// pkg/wazuh/setup/checks.go
// Verification functions for Wazuh integration
//
// Created by Code Monkey Cybersecurity
// ABN: 77 177 673 061

package setup

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// CheckWazuhInstalled verifies that Wazuh is properly installed and running
func CheckWazuhInstalled(rc *eos_io.RuntimeContext) error {
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

// TestIntegration verifies that the webhook integration is working
func TestIntegration(rc *eos_io.RuntimeContext, config *Config) error {
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
	integrationPath := config.IntegrationsDir + "/" + config.IntegrationName
	logger.Debug("Testing integration script", zap.String("path", integrationPath))

	cmd = exec.Command(integrationPath, testFile, "debug")
	output, err = cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("integration test failed: %w\n%s", err, string(output))
	}

	logger.Info("Integration test successful")

	return nil
}
