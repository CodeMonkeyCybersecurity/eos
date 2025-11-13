// pkg/consul/service/lifecycle.go
// Consul service lifecycle management (start, stop, restart, enable)

package service

import (
	"context"
	"fmt"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/hashicorp/consul/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// LifecycleManager handles Consul service lifecycle operations
type LifecycleManager struct {
	rc      *eos_io.RuntimeContext
	logger  otelzap.LoggerWithCtx
	systemd *SystemdManager
}

// NewLifecycleManager creates a new lifecycle manager
func NewLifecycleManager(rc *eos_io.RuntimeContext) *LifecycleManager {
	return &LifecycleManager{
		rc:      rc,
		logger:  otelzap.Ctx(rc.Ctx),
		systemd: NewSystemdManager(rc, "consul"),
	}
}

// Start starts the Consul service and waits for it to be ready
func (lm *LifecycleManager) Start() error {
	lm.logger.Info("Starting Consul service")

	if err := lm.systemd.Start(); err != nil {
		// Get service status for debugging
		if status, statusErr := lm.systemd.GetStatus(); statusErr == nil {
			lm.logger.Error("Failed to start Consul service",
				zap.String("status", status))
		}
		return fmt.Errorf("failed to start service: %w", err)
	}

	// Wait for Consul to be ready
	return lm.WaitForReady(30 * time.Second)
}

// Stop stops the Consul service
func (lm *LifecycleManager) Stop() error {
	lm.logger.Info("Stopping Consul service")

	if err := lm.systemd.Stop(); err != nil {
		return fmt.Errorf("failed to stop service: %w", err)
	}

	// Wait for service to fully stop
	deadline := time.Now().Add(10 * time.Second)
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	for time.Now().Before(deadline) {
		if !lm.systemd.IsActive() {
			lm.logger.Info("Service stopped successfully")
			return nil
		}
		<-ticker.C
	}

	return fmt.Errorf("service failed to stop within 10 seconds")
}

// Restart performs a graceful restart of Consul
func (lm *LifecycleManager) Restart() error {
	lm.logger.Info("Restarting Consul service")

	// Gracefully stop
	if err := lm.Stop(); err != nil {
		return fmt.Errorf("failed to stop Consul: %w", err)
	}

	// Wait a moment
	time.Sleep(2 * time.Second)

	// Start again
	if err := lm.Start(); err != nil {
		return fmt.Errorf("failed to start Consul: %w", err)
	}

	lm.logger.Info("Consul restarted successfully")
	return nil
}

// Enable enables the Consul service to start on boot
func (lm *LifecycleManager) Enable() error {
	lm.logger.Info("Enabling Consul service")
	return lm.systemd.Enable()
}

// WaitForReady waits for Consul to be ready to accept requests
func (lm *LifecycleManager) WaitForReady(timeout time.Duration) error {
	lm.logger.Info("Waiting for Consul to be ready",
		zap.Duration("timeout", timeout))

	ctx, cancel := context.WithTimeout(lm.rc.Ctx, timeout)
	defer cancel()

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout waiting for Consul to be ready")
		case <-ticker.C:
			if lm.IsReady() {
				lm.logger.Info("Consul is ready")
				return nil
			}
		}
	}
}

// IsReady checks if Consul is ready to accept requests
func (lm *LifecycleManager) IsReady() bool {
	config := api.DefaultConfig()
	config.Address = fmt.Sprintf("%s:%d", shared.GetInternalHostname(), shared.PortConsul)

	client, err := api.NewClient(config)
	if err != nil {
		return false
	}

	// Check agent status
	_, err = client.Agent().Self()
	return err == nil
}

// IsActive checks if the Consul service is active
func (lm *LifecycleManager) IsActive() bool {
	return lm.systemd.IsActive()
}

// GetStatus returns the current service status
func (lm *LifecycleManager) GetStatus() (string, error) {
	return lm.systemd.GetStatus()
}
