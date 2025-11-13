// pkg/wazuh/version_config.go
//
// Wazuh Version Configuration Management
//
// This file provides version configuration management for Wazuh deployments.
// Since Wazuh is your own implementation of Wazuh, this handles version
// policies, update schedules, and configuration templates.

package wazuh

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/xdg"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// UpdatePolicy defines version update policies
type UpdatePolicy string

const (
	UpdatePolicyManual UpdatePolicy = "manual"
	UpdatePolicyPatch  UpdatePolicy = "patch"
	UpdatePolicyMinor  UpdatePolicy = "minor"
	UpdatePolicyMajor  UpdatePolicy = "major"
	UpdatePolicyLatest UpdatePolicy = "latest"
)

// VersionConfig represents Wazuh version configuration
type VersionConfig struct {
	CurrentVersion     string        `json:"current_version"`
	UpdatePolicy       UpdatePolicy  `json:"update_policy"`
	AutoUpdate         bool          `json:"auto_update"`
	RequireApproval    bool          `json:"require_approval"`
	BackupBeforeUpdate bool          `json:"backup_before_update"`
	TestEnvironment    bool          `json:"test_environment"`
	PinnedVersion      string        `json:"pinned_version,omitempty"`
	MinimumVersion     string        `json:"minimum_version,omitempty"`
	MaximumVersion     string        `json:"maximum_version,omitempty"`
	MaintenanceWindow  *TimeWindow   `json:"maintenance_window,omitempty"`
	CacheTimeout       time.Duration `json:"cache_timeout"`
	LastChecked        time.Time     `json:"last_checked"`
	LastUpdated        time.Time     `json:"last_updated"`
	NotifyOnUpdate     bool          `json:"notify_on_update"`
	NotifyChannels     []string      `json:"notify_channels,omitempty"`
}

// TimeWindow defines maintenance window for updates
type TimeWindow struct {
	StartHour int    `json:"start_hour"`
	EndHour   int    `json:"end_hour"`
	Days      []int  `json:"days"` // 0=Sunday, 1=Monday, etc.
	Timezone  string `json:"timezone"`
}

// ConfigManager handles Wazuh version configuration
type ConfigManager struct {
	configPath string
}

// NewConfigManager creates a new configuration manager
func NewConfigManager() *ConfigManager {
	configPath := xdg.XDGConfigPath(shared.EosID, "wazuh-version.json")
	return &ConfigManager{
		configPath: configPath,
	}
}

// LoadConfig loads the version configuration
func (cm *ConfigManager) LoadConfig(rc *eos_io.RuntimeContext) (*VersionConfig, error) {
	logger := otelzap.Ctx(rc.Ctx)

	if _, err := os.Stat(cm.configPath); os.IsNotExist(err) {
		logger.Info("No version config found, using defaults")
		return DefaultVersionConfig(), nil
	}

	data, err := os.ReadFile(cm.configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config VersionConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	logger.Info("Loaded Wazuh version configuration",
		zap.String("policy", string(config.UpdatePolicy)),
		zap.String("current_version", config.CurrentVersion))

	return &config, nil
}

// SaveConfig saves the version configuration
func (cm *ConfigManager) SaveConfig(rc *eos_io.RuntimeContext, config *VersionConfig) error {
	logger := otelzap.Ctx(rc.Ctx)

	// Create config directory if it doesn't exist
	configDir := filepath.Dir(cm.configPath)
	if err := os.MkdirAll(configDir, shared.ServiceDirPerm); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(cm.configPath, data, shared.ConfigFilePerm); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	logger.Info("Saved Wazuh version configuration", zap.String("path", cm.configPath))
	return nil
}

// ShouldUpdate checks if an update should be performed based on policy
func (cm *ConfigManager) ShouldUpdate(rc *eos_io.RuntimeContext, currentVersion, latestVersion string, versionManager *VersionManager) (bool, string, error) {
	config, err := cm.LoadConfig(rc)
	if err != nil {
		return false, "", err
	}

	// Check if version is pinned
	if config.PinnedVersion != "" {
		if latestVersion != config.PinnedVersion {
			return false, fmt.Sprintf("version pinned to %s", config.PinnedVersion), nil
		}
	}

	// Check version constraints
	if config.MinimumVersion != "" {
		if versionManager.compareVersions(latestVersion, config.MinimumVersion) < 0 {
			return false, fmt.Sprintf("version %s below minimum %s", latestVersion, config.MinimumVersion), nil
		}
	}

	if config.MaximumVersion != "" {
		if versionManager.compareVersions(latestVersion, config.MaximumVersion) > 0 {
			return false, fmt.Sprintf("version %s above maximum %s", latestVersion, config.MaximumVersion), nil
		}
	}

	// Check update policy
	switch config.UpdatePolicy {
	case UpdatePolicyManual:
		return false, "manual update policy requires explicit approval", nil
	case UpdatePolicyPatch:
		// Allow patch updates only
		return versionManager.isPatchUpdate(currentVersion, latestVersion), "policy allows patch updates only", nil
	case UpdatePolicyMinor:
		// Allow minor and patch updates
		return versionManager.isMinorOrPatchUpdate(currentVersion, latestVersion), "policy allows minor/patch updates only", nil
	case UpdatePolicyMajor:
		// Allow major, minor, and patch updates
		return versionManager.isMajorMinorOrPatchUpdate(currentVersion, latestVersion), "policy allows major/minor/patch updates", nil
	case UpdatePolicyLatest:
		// Allow any update
		return true, "policy allows latest version", nil
	default:
		return false, "unknown update policy", nil
	}
}

// DefaultVersionConfig returns default version configuration
func DefaultVersionConfig() *VersionConfig {
	return &VersionConfig{
		CurrentVersion:     DefaultWazuhVersion,
		UpdatePolicy:       UpdatePolicyManual,
		AutoUpdate:         false,
		RequireApproval:    true,
		BackupBeforeUpdate: true,
		TestEnvironment:    false,
		CacheTimeout:       1 * time.Hour,
		LastChecked:        time.Time{},
		LastUpdated:        time.Time{},
	}
}

// Helper methods for version comparison (simplified implementations)
func (vm *VersionManager) isPatchUpdate(current, latest string) bool {
	// Simple implementation - would need proper semver parsing
	return vm.compareVersions(latest, current) > 0
}

func (vm *VersionManager) isMinorOrPatchUpdate(current, latest string) bool {
	// Simple implementation - would need proper semver parsing
	return vm.compareVersions(latest, current) > 0
}

func (vm *VersionManager) isMajorMinorOrPatchUpdate(current, latest string) bool {
	// Simple implementation - would need proper semver parsing
	return vm.compareVersions(latest, current) > 0
}
