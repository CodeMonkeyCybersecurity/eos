// pkg/wazuh/setup/service.go
// Service management for Wazuh integration
//
// Created by Code Monkey Cybersecurity
// ABN: 77 177 673 061

package setup

import (
	"fmt"
	"os/exec"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// RestartWazuhManager restarts the wazuh-manager service
func RestartWazuhManager(rc *eos_io.RuntimeContext) error {
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
