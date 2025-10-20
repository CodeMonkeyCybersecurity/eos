// pkg/wazuh/ossec/validate.go

package ossec

import (
	"encoding/xml"
	"fmt"
	"os"
	"os/exec"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ValidateXML validates the XML structure of the ossec.conf content
//
// This performs basic XML syntax validation
func ValidateXML(rc *eos_io.RuntimeContext, content []byte) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Debug("Validating XML structure", zap.Int("size_bytes", len(content)))

	var config OssecConfig
	if err := xml.Unmarshal(content, &config); err != nil {
		return fmt.Errorf("XML syntax validation failed: %w", err)
	}

	logger.Debug("XML structure is valid")
	return nil
}

// TestWazuhConfig tests the configuration using Wazuh's built-in validator
//
// This function implements the Assess → Intervene → Evaluate pattern:
// - Assess: Check if wazuh-control binary exists
// - Intervene: Run wazuh-control with test option
// - Evaluate: Check command exit status and output
func TestWazuhConfig(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Testing configuration with Wazuh validator")

	// Assess: Check if wazuh-control exists
	wazuhControl := "/var/ossec/bin/wazuh-control"
	if _, err := os.Stat(wazuhControl); err != nil {
		return fmt.Errorf("wazuh-control not found at %s: %w", wazuhControl, err)
	}

	// Intervene: Run configuration test
	cmd := exec.Command(wazuhControl, "configtest")
	output, err := cmd.CombinedOutput()

	logger.Debug("Wazuh config test output",
		zap.String("output", string(output)),
		zap.Error(err))

	// Evaluate: Check result
	if err != nil {
		return fmt.Errorf("wazuh configuration test failed: %s\nError: %w", string(output), err)
	}

	logger.Info("Configuration validated successfully by Wazuh")
	return nil
}

// RestartWazuhServices restarts the Wazuh manager service
//
// This function implements the Assess → Intervene → Evaluate pattern:
// - Assess: Check if systemctl is available
// - Intervene: Restart wazuh-manager service
// - Evaluate: Verify service restarted successfully
func RestartWazuhServices(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Restarting Wazuh manager service")

	// Intervene: Restart service
	cmd := exec.Command("systemctl", "restart", "wazuh-manager")
	output, err := cmd.CombinedOutput()

	if err != nil {
		logger.Error("Failed to restart Wazuh manager",
			zap.String("output", string(output)),
			zap.Error(err))
		return fmt.Errorf("failed to restart wazuh-manager: %s\nError: %w", string(output), err)
	}

	// Evaluate: Check service status
	statusCmd := exec.Command("systemctl", "is-active", "wazuh-manager")
	if err := statusCmd.Run(); err != nil {
		logger.Warn("Wazuh manager may not be running after restart")
		return fmt.Errorf("wazuh-manager service check failed after restart: %w", err)
	}

	logger.Info("Wazuh manager restarted successfully")
	return nil
}

// HasUpdates checks if the UpdateOptions contains any configuration changes
func HasUpdates(opts *UpdateOptions) bool {
	return opts.Global != nil ||
		opts.Remote != nil ||
		opts.Vulnerability != nil ||
		len(opts.Integrations) > 0 ||
		opts.Syscheck != nil ||
		opts.Syslog != nil ||
		opts.ActiveResponse != nil ||
		len(opts.Localfiles) > 0 ||
		len(opts.Wodles) > 0
}
