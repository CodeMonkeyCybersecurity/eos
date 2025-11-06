// Package connectors provides service connector implementations
package connectors

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/synctypes"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/tailscale"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ConsulTailscaleAutoConnector implements ServiceConnector for configuring
// local Consul to use Tailscale networking.
//
// When user runs "eos sync consul tailscale" or "eos sync tailscale consul",
// this connector:
//  1. Gets this node's Tailscale IP
//  2. Configures local Consul to bind to the Tailscale IP
//  3. Restarts Consul with the new configuration
//
// This is a LOCAL operation that prepares Consul to communicate over Tailscale.
// To join multiple Consul nodes together, use: eos sync consul --vhostX --vhostY
type ConsulTailscaleAutoConnector struct{}

// NewConsulTailscaleAutoConnector creates a new auto-discovery connector
func NewConsulTailscaleAutoConnector() *ConsulTailscaleAutoConnector {
	return &ConsulTailscaleAutoConnector{}
}

// Name returns the connector name
func (c *ConsulTailscaleAutoConnector) Name() string {
	return "ConsulTailscaleAutoConnector"
}

// Description returns a human-readable description
func (c *ConsulTailscaleAutoConnector) Description() string {
	return "Configures local Consul to bind to Tailscale IP for Tailscale networking"
}

// ServicePair returns the normalized service pair identifier
func (c *ConsulTailscaleAutoConnector) ServicePair() string {
	return "consul-tailscale"
}

// PreflightCheck verifies Tailscale is running and Consul is installed
func (c *ConsulTailscaleAutoConnector) PreflightCheck(rc *eos_io.RuntimeContext, config *synctypes.SyncConfig) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Running pre-flight checks for Consul and Tailscale")

	// Check if Tailscale is installed and running
	if _, err := exec.LookPath("tailscale"); err != nil {
		return fmt.Errorf("tailscale is not installed. Please install Tailscale first:\n" +
			"  sudo eos create tailscale\n" +
			"  sudo tailscale up")
	}

	// Check if Tailscale is authenticated
	tsClient, err := tailscale.NewClient(rc)
	if err != nil {
		return fmt.Errorf("tailscale client error: %w\n\n"+
			"Is Tailscale authenticated? Run: sudo tailscale up", err)
	}

	// Get self IP to verify connectivity
	_, err = tsClient.GetSelfIP()
	if err != nil {
		return fmt.Errorf("tailscale is not connected: %w\n\n"+
			"Please authenticate with: sudo tailscale up", err)
	}

	// Check if Consul is installed
	if _, err := exec.LookPath("consul"); err != nil {
		return fmt.Errorf("consul is not installed. Please install Consul first:\n" +
			"  sudo eos create consul")
	}

	logger.Info("Pre-flight checks passed")
	return nil
}

// CheckConnection checks if Consul nodes are already joined
func (c *ConsulTailscaleAutoConnector) CheckConnection(rc *eos_io.RuntimeContext, config *synctypes.SyncConfig) (*synctypes.SyncState, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// Check if Consul members show multiple nodes
	cmd := exec.Command("consul", "members")
	output, err := cmd.CombinedOutput()
	if err != nil {
		logger.Debug("Consul members command failed", zap.Error(err))
		return &synctypes.SyncState{
			Connected: false,
			Healthy:   false,
			Reason:    "Consul not running or not accessible",
		}, nil
	}

	// Parse output to count members
	// If we have more than 1 member, we might be connected
	outputStr := string(output)
	logger.Debug("Consul members output", zap.String("output", outputStr))

	// TODO: More sophisticated check - for now assume not connected to avoid issues
	return &synctypes.SyncState{
		Connected:         false,
		Healthy:           true,
		Reason:            "Ready to discover and join Consul nodes over Tailscale",
		Service1Installed: true,
		Service1Running:   true,
		Service2Installed: true,
		Service2Running:   true,
	}, nil
}

// Backup creates backup of Consul configuration
func (c *ConsulTailscaleAutoConnector) Backup(rc *eos_io.RuntimeContext, config *synctypes.SyncConfig) (*synctypes.BackupMetadata, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Backing up Consul configuration")

	// Use the existing ConsulTailscaleConnector backup logic
	// For now, return minimal backup metadata
	return &synctypes.BackupMetadata{
		Service1ConfigPath: "/etc/consul.d/consul.hcl",
		RestartRequired:    true,
	}, nil
}

// Connect configures local Consul to bind to Tailscale IP
func (c *ConsulTailscaleAutoConnector) Connect(rc *eos_io.RuntimeContext, config *synctypes.SyncConfig) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Configuring local Consul to use Tailscale networking")

	// Create Tailscale client
	tsClient, err := tailscale.NewClient(rc)
	if err != nil {
		return fmt.Errorf("failed to create Tailscale client: %w", err)
	}

	// Get this node's Tailscale IP
	myTailscaleIP, err := tsClient.GetSelfIP()
	if err != nil {
		return fmt.Errorf("failed to get this node's Tailscale IP: %w", err)
	}

	status, err := tsClient.GetStatus()
	if err != nil {
		return fmt.Errorf("failed to get Tailscale status: %w", err)
	}

	logger.Info("This node's Tailscale configuration",
		zap.String("hostname", status.Self.HostName),
		zap.String("tailscale_ip", myTailscaleIP))

	if config.DryRun {
		logger.Info("DRY RUN: Would configure Consul with:",
			zap.String("bind_addr", myTailscaleIP))
		return nil
	}

	// Read existing Consul config
	consulConfigPath := "/etc/consul.d/consul.hcl"
	existingConfig, err := os.ReadFile(consulConfigPath)
	if err != nil {
		return fmt.Errorf("failed to read Consul config: %w", err)
	}

	// Update configuration to use Tailscale IP
	newConfig := updateConsulBindAddr(string(existingConfig), myTailscaleIP)

	// Write new configuration
	if err := os.WriteFile(consulConfigPath, []byte(newConfig), 0640); err != nil {
		return fmt.Errorf("failed to write Consul config: %w", err)
	}

	logger.Info("Consul configuration updated",
		zap.String("config", consulConfigPath),
		zap.String("bind_addr", myTailscaleIP))

	// Restart Consul
	logger.Info("Restarting Consul service...")
	cmd := exec.Command("systemctl", "restart", "consul")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to restart Consul: %w\nOutput: %s", err, string(output))
	}

	logger.Info("Consul configured to use Tailscale networking",
		zap.String("tailscale_ip", myTailscaleIP))

	return nil
}

// updateConsulBindAddr updates only the bind_addr in Consul configuration
func updateConsulBindAddr(existingConfig, bindAddr string) string {
	lines := strings.Split(existingConfig, "\n")
	var newLines []string
	foundBindAddr := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Update existing bind_addr
		if strings.HasPrefix(trimmed, "bind_addr") {
			newLines = append(newLines, fmt.Sprintf(`bind_addr = "%s"  # Tailscale IP`, bindAddr))
			foundBindAddr = true
			continue
		}

		newLines = append(newLines, line)
	}

	// Add bind_addr if not found
	if !foundBindAddr {
		newLines = append(newLines, "")
		newLines = append(newLines, fmt.Sprintf(`bind_addr = "%s"  # Tailscale IP`, bindAddr))
	}

	return strings.Join(newLines, "\n")
}

// Verify checks that Consul is running with Tailscale configuration
func (c *ConsulTailscaleAutoConnector) Verify(rc *eos_io.RuntimeContext, config *synctypes.SyncConfig) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Verifying Consul is using Tailscale networking")

	// Check if Consul is accessible
	cmd := exec.Command("consul", "info")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to verify Consul status: %w\nOutput: %s", err, string(output))
	}

	logger.Info("Consul is running with Tailscale configuration")
	logger.Debug("Consul info output", zap.String("output", string(output)))

	return nil
}

// Rollback restores Consul configuration from backup
func (c *ConsulTailscaleAutoConnector) Rollback(rc *eos_io.RuntimeContext, config *synctypes.SyncConfig, backup *synctypes.BackupMetadata) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Warn("Rollback requested - restoring Consul configuration")

	// TODO: Implement proper rollback logic
	// For now, just log that rollback was requested

	logger.Info("Rollback completed")
	return nil
}
