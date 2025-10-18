// pkg/consul/lifecycle/verification.go
// Post-installation verification for Consul

package lifecycle

import (
	"fmt"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	consulapi "github.com/hashicorp/consul/api"
	"go.uber.org/zap"
)

// verify performs post-installation verification
func (ci *ConsulInstaller) verify() error {
	ci.logger.Info("Verifying Consul installation")

	// Check service status
	if !ci.systemd.IsActive() {
		return fmt.Errorf("consul service is not active")
	}

	ci.logger.Info("Consul service is active")

	// Wait for Consul to be ready
	ci.logger.Info("Waiting for Consul to be ready")
	timeout := time.After(30 * time.Second)
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-timeout:
			return fmt.Errorf("timeout waiting for Consul to be ready")
		case <-ticker.C:
			if ci.isConsulReady() {
				ci.logger.Info("Consul is ready and responding")
				return nil
			}
		}
	}
}

// isConsulReady checks if Consul is ready to accept requests
func (ci *ConsulInstaller) isConsulReady() bool {
	// Try to connect to the API
	config := consulapi.DefaultConfig()
	config.Address = fmt.Sprintf("127.0.0.1:%d", shared.PortConsul)

	client, err := consulapi.NewClient(config)
	if err != nil {
		return false
	}

	_, err = client.Agent().Self()
	return err == nil
}

// verifyDirectoryOwnership verifies that a directory has correct ownership
func (ci *ConsulInstaller) verifyDirectoryOwnership(path, expectedOwner string) error {
	// Get directory stat info
	fileInfo, err := ci.runner.RunOutput("stat", "-c", "%U", path)
	if err != nil {
		return fmt.Errorf("failed to get ownership info for %s: %w", path, err)
	}

	owner := fileInfo
	if owner != expectedOwner {
		return fmt.Errorf("directory %s has incorrect ownership: expected %s, got %s", path, expectedOwner, owner)
	}

	ci.logger.Info("Directory ownership verified",
		zap.String("path", path),
		zap.String("owner", owner))

	return nil
}
