// pkg/bootstrap/storage_integration.go

package bootstrap

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/environment"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

// DeployStorageOps deploys storage operations configuration during bootstrap
func DeployStorageOps(rc *eos_io.RuntimeContext, info *ClusterInfo) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Deploying storage operations configuration",
		zap.Bool("single_node", info.IsSingleNode),
		zap.String("role", string(info.MyRole)))

	// Create environment struct
	env := &environment.Environment{
		MachineCount: info.NodeCount,
		MyRole:       info.MyRole,
		MyHostname:   getHostname(),
	}

	// Get storage profile
	profile := env.GetStorageProfile()

	// Deploy configuration file
	if err := deployStorageConfig(rc, profile, env); err != nil {
		return fmt.Errorf("failed to deploy storage config: %w", err)
	}

	// Deploy monitoring service
	if err := deployMonitoringService(rc); err != nil {
		return fmt.Errorf("failed to deploy monitoring service: %w", err)
	}

	// Set Consul storage configuration (HashiCorp migration)
	logger.Info("Configuring storage via Consul service discovery")
	// TODO: Implement Consul-based storage configuration

	// Deploy Nomad jobs (replacing  states)
	logger.Info("Deploying storage jobs via Nomad")
	// TODO: Implement Nomad job deployment for storage services

	logger.Info("Storage operations deployed successfully")
	return nil
}

// deployStorageConfig creates the storage-ops.yaml configuration
func deployStorageConfig(rc *eos_io.RuntimeContext, profile environment.StorageProfile, env *environment.Environment) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Read the default config
	defaultConfig, err := os.ReadFile("/opt/eos/configs/storage-ops.yaml")
	if err != nil {
		logger.Warn("Default storage config not found, generating from template",
			zap.Error(err))
		defaultConfig = []byte(generateDefaultConfig())
	}

	// Parse and modify for environment
	var config map[string]interface{}
	if err := yaml.Unmarshal(defaultConfig, &config); err != nil {
		return fmt.Errorf("failed to parse config: %w", err)
	}

	// Update thresholds based on environment
	if storage, ok := config["storage"].(map[string]interface{}); ok {
		storage["thresholds"] = map[string]interface{}{
			"warning":   profile.DefaultThresholds.Warning,
			"compress":  profile.DefaultThresholds.Compress,
			"cleanup":   profile.DefaultThresholds.Cleanup,
			"degraded":  profile.DefaultThresholds.Degraded,
			"emergency": profile.DefaultThresholds.Emergency,
			"critical":  profile.DefaultThresholds.Critical,
		}

		// Update monitoring interval
		if monitor, ok := storage["monitor"].(map[string]interface{}); ok {
			monitor["interval"] = profile.MonitoringInterval
		}
	}

	// Marshal back to YAML
	configData, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	// Ensure directory exists
	configDir := "/etc/eos"
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("failed to create config dir: %w", err)
	}

	// Write configuration
	configPath := filepath.Join(configDir, "storage-ops.yaml")
	if err := os.WriteFile(configPath, configData, 0644); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	logger.Info("Storage configuration deployed",
		zap.String("path", configPath),
		zap.String("scale", string(profile.Scale)))

	return nil
}

// deployMonitoringService creates the systemd service for storage monitoring
func deployMonitoringService(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)

	serviceContent := `[Unit]
Description=EOS Storage Monitoring Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/eos read storage-monitor --daemon --interval=5m
Restart=always
RestartSec=30
User=root
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
`

	servicePath := "/etc/systemd/system/eos-storage-monitor.service"
	if err := os.WriteFile(servicePath, []byte(serviceContent), 0644); err != nil {
		return fmt.Errorf("failed to write service file: %w", err)
	}

	// Reload systemd
	if err := SystemctlDaemonReload(rc); err != nil {
		return fmt.Errorf("failed to reload systemd: %w", err)
	}

	// Enable service (but don't start yet)
	if err := SystemctlEnable(rc, "eos-storage-monitor.service"); err != nil {
		logger.Warn("Failed to enable storage monitor service", zap.Error(err))
	}

	logger.Info("Storage monitoring service deployed")
	return nil
}

// generateDefaultConfig generates a minimal default configuration
func generateDefaultConfig() string {
	return `storage:
  monitor:
    interval: 5m
    history_retention: 7d
  classification:
    critical:
      - /etc
      - /var/lib/mysql
      - /var/lib/postgresql
    important:
      - /var/log
      - /var/backups
    expendable:
      - /tmp
      - /var/tmp
  cleanup:
    docker:
      prune_until: 72h
    logs:
      compress_after: 7d
      delete_after: 30d
`
}

// getHostname returns the system hostname
func getHostname() string {
	h, _ := os.Hostname()
	return h
}
