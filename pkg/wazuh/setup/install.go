// pkg/wazuh/setup/install.go
// Main installation logic for Wazuh webhook integration
//
// Created by Code Monkey Cybersecurity
// ABN: 77 177 673 061

package setup

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Install sets up Wazuh webhook integration following Assess → Intervene → Evaluate pattern
func Install(rc *eos_io.RuntimeContext, config *Config, hookURLFlag string) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Starting Wazuh webhook integration setup")

	// ASSESS - Check prerequisites
	logger.Info("Phase 1: ASSESS - Checking prerequisites")
	if err := CheckWazuhInstalled(rc); err != nil {
		return fmt.Errorf("wazuh prerequisite check failed: %w", err)
	}

	// Get webhook URL
	if err := GetWebhookURL(rc, config, hookURLFlag); err != nil {
		return fmt.Errorf("failed to configure webhook URL: %w", err)
	}

	// Generate secure token
	if err := GenerateWebhookToken(rc, config); err != nil {
		return fmt.Errorf("failed to generate webhook token: %w", err)
	}

	// INTERVENE - Install and configure
	logger.Info("Phase 2: INTERVENE - Installing integration")

	if err := InstallIntegrationScripts(rc, config); err != nil {
		return fmt.Errorf("failed to install integration scripts: %w", err)
	}

	if err := CreateEnvFile(rc, config); err != nil {
		return fmt.Errorf("failed to create .env file: %w", err)
	}

	if err := InstallPythonDependencies(rc); err != nil {
		return fmt.Errorf("failed to install Python dependencies: %w", err)
	}

	if err := UpdateOssecConf(rc, config); err != nil {
		return fmt.Errorf("failed to update ossec.conf: %w", err)
	}

	// EVALUATE - Test and restart
	logger.Info("Phase 3: EVALUATE - Testing integration")

	if err := TestIntegration(rc, config); err != nil {
		logger.Warn("Integration test failed", zap.Error(err))
		logger.Warn("You may need to verify the webhook URL is accessible")
	}

	// Prompt for restart if not auto
	if !config.AutoRestart {
		logger.Info("Restart required",
			zap.String("prompt", "Restart wazuh-manager now?"))
		if PromptYesNo("Restart wazuh-manager now?") {
			config.AutoRestart = true
		}
	}

	if config.AutoRestart {
		logger.Info("Restarting wazuh-manager")
		if err := RestartWazuhManager(rc); err != nil {
			return fmt.Errorf("failed to restart wazuh-manager: %w", err)
		}
		logger.Info("Wazuh manager restarted successfully")
	}

	PrintWazuhSuccessMessage(logger, config)

	return nil
}
