// pkg/bootstrap/storage_integration.go

package bootstrap

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/environment"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
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

	// Set Salt grains for storage configuration
	if err := setStorageGrains(rc, env, profile); err != nil {
		return fmt.Errorf("failed to set storage grains: %w", err)
	}

	// Deploy Salt states
	if err := deploySaltStates(rc); err != nil {
		return fmt.Errorf("failed to deploy salt states: %w", err)
	}

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
	if _, err := execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"daemon-reload"},
		Capture: false,
	}); err != nil {
		return fmt.Errorf("failed to reload systemd: %w", err)
	}

	// Enable service (but don't start yet)
	if _, err := execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"enable", "eos-storage-monitor.service"},
		Capture: false,
	}); err != nil {
		logger.Warn("Failed to enable storage monitor service", zap.Error(err))
	}

	logger.Info("Storage monitoring service deployed")
	return nil
}

// setStorageGrains sets Salt grains for storage configuration
func setStorageGrains(rc *eos_io.RuntimeContext, env *environment.Environment, profile environment.StorageProfile) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Set role grain
	if _, err := execute.Run(rc.Ctx, execute.Options{
		Command: "salt-call",
		Args:    []string{"--local", "grains.set", "role", string(env.MyRole)},
		Capture: false,
	}); err != nil {
		logger.Warn("Failed to set role grain", zap.Error(err))
	}

	// Set scale grain
	if _, err := execute.Run(rc.Ctx, execute.Options{
		Command: "salt-call",
		Args:    []string{"--local", "grains.set", "scale", string(profile.Scale)},
		Capture: false,
	}); err != nil {
		logger.Warn("Failed to set scale grain", zap.Error(err))
	}

	// Set storage thresholds as grain
	thresholdData := fmt.Sprintf("warning:%v,compress:%v,cleanup:%v,degraded:%v,emergency:%v,critical:%v",
		profile.DefaultThresholds.Warning,
		profile.DefaultThresholds.Compress,
		profile.DefaultThresholds.Cleanup,
		profile.DefaultThresholds.Degraded,
		profile.DefaultThresholds.Emergency,
		profile.DefaultThresholds.Critical)
	
	if _, err := execute.Run(rc.Ctx, execute.Options{
		Command: "salt-call",
		Args:    []string{"--local", "grains.set", "storage_thresholds", thresholdData},
		Capture: false,
	}); err != nil {
		logger.Warn("Failed to set storage thresholds grain", zap.Error(err))
	}

	logger.Info("Salt grains configured for storage")
	return nil
}

// deploySaltStates creates Salt states for storage operations
func deploySaltStates(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Ensure Salt states directory exists
	statesDir := "/srv/salt/storage"
	if err := os.MkdirAll(statesDir, 0755); err != nil {
		return fmt.Errorf("failed to create states dir: %w", err)
	}

	// Create init.sls
	initState := `# storage/init.sls
# EOS Storage Operations Salt State

include:
  - .config
  - .monitor
  - .thresholds

storage_ops_package:
  pkg.installed:
    - name: eos
    - require_in:
      - file: storage_config_file
      - service: storage_monitor_service
`

	if err := os.WriteFile(filepath.Join(statesDir, "init.sls"), []byte(initState), 0644); err != nil {
		return fmt.Errorf("failed to write init.sls: %w", err)
	}

	// Create config.sls
	configState := `# storage/config.sls
# Deploy storage configuration

storage_config_file:
  file.managed:
    - name: /etc/eos/storage-ops.yaml
    - source: salt://storage/files/storage-ops.yaml.jinja
    - template: jinja
    - context:
        role: {{ grains.get('role', 'monolith') }}
        scale: {{ grains.get('scale', 'single') }}
        thresholds: {{ grains.get('storage_thresholds', {}) }}
    - makedirs: True
`

	if err := os.WriteFile(filepath.Join(statesDir, "config.sls"), []byte(configState), 0644); err != nil {
		return fmt.Errorf("failed to write config.sls: %w", err)
	}

	// Create monitor.sls
	monitorState := `# storage/monitor.sls
# Storage monitoring service

storage_monitor_service:
  file.managed:
    - name: /etc/systemd/system/eos-storage-monitor.service
    - source: salt://storage/files/storage-monitor.service
  service.running:
    - name: eos-storage-monitor
    - enable: True
    - watch:
      - file: storage_config_file
      - file: storage_monitor_service
`

	if err := os.WriteFile(filepath.Join(statesDir, "monitor.sls"), []byte(monitorState), 0644); err != nil {
		return fmt.Errorf("failed to write monitor.sls: %w", err)
	}

	logger.Info("Salt states deployed for storage operations")
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