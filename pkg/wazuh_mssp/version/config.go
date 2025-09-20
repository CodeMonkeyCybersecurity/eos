// pkg/wazuh_mssp/version/config.go
package version

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// UpdatePolicy defines how versions should be updated
type UpdatePolicy string

const (
	UpdatePolicyManual    UpdatePolicy = "manual"    // Never auto-update
	UpdatePolicyPatch     UpdatePolicy = "patch"     // Auto-update patch versions (4.13.0 -> 4.13.1)
	UpdatePolicyMinor     UpdatePolicy = "minor"     // Auto-update minor versions (4.13.0 -> 4.14.0)
	UpdatePolicyMajor     UpdatePolicy = "major"     // Auto-update major versions (4.13.0 -> 5.0.0)
	UpdatePolicyLatest    UpdatePolicy = "latest"    // Always use latest stable
)

// VersionConfig contains version management configuration
type VersionConfig struct {
	// Version pinning
	PinnedVersion    string       `json:"pinned_version,omitempty"`    // Pin to specific version
	MinimumVersion   string       `json:"minimum_version,omitempty"`   // Minimum allowed version
	MaximumVersion   string       `json:"maximum_version,omitempty"`   // Maximum allowed version
	UpdatePolicy     UpdatePolicy `json:"update_policy"`               // How to handle updates
	
	// Update scheduling
	AutoUpdate       bool          `json:"auto_update"`                 // Enable automatic updates
	UpdateSchedule   string        `json:"update_schedule,omitempty"`   // Cron-like schedule
	MaintenanceWindow *TimeWindow  `json:"maintenance_window,omitempty"` // When updates are allowed
	
	// Safety settings
	RequireApproval  bool          `json:"require_approval"`            // Require manual approval
	TestEnvironment  bool          `json:"test_environment"`            // Is this a test environment
	BackupBeforeUpdate bool        `json:"backup_before_update"`        // Backup before updating
	
	// Notification settings
	NotifyOnUpdate   bool          `json:"notify_on_update"`            // Notify when updates available
	NotifyChannels   []string      `json:"notify_channels,omitempty"`   // Where to send notifications
	
	// Cache settings
	CacheTimeout     time.Duration `json:"cache_timeout"`               // How long to cache version info
	
	// Last update tracking
	LastChecked      time.Time     `json:"last_checked"`                // When versions were last checked
	LastUpdated      time.Time     `json:"last_updated"`                // When last updated
	CurrentVersion   string        `json:"current_version"`             // Currently installed version
}

// TimeWindow defines a time window for maintenance
type TimeWindow struct {
	StartHour int    `json:"start_hour"` // 0-23
	EndHour   int    `json:"end_hour"`   // 0-23
	Days      []int  `json:"days"`       // 0=Sunday, 1=Monday, etc.
	Timezone  string `json:"timezone"`   // IANA timezone
}

// DefaultVersionConfig returns a sensible default configuration
func DefaultVersionConfig() *VersionConfig {
	return &VersionConfig{
		UpdatePolicy:       UpdatePolicyPatch,  // Safe default: only patch updates
		AutoUpdate:         false,              // Require manual updates by default
		RequireApproval:    true,               // Require approval for safety
		TestEnvironment:    false,              // Assume production
		BackupBeforeUpdate: true,               // Always backup
		NotifyOnUpdate:     true,               // Notify about updates
		CacheTimeout:       1 * time.Hour,      // Cache for 1 hour
		MaintenanceWindow: &TimeWindow{
			StartHour: 2,                       // 2 AM
			EndHour:   4,                       // 4 AM
			Days:      []int{0, 6},             // Sunday and Saturday
			Timezone:  "UTC",
		},
	}
}

// ConfigManager handles version configuration
type ConfigManager struct {
	configPath string
}

// NewConfigManager creates a new configuration manager
func NewConfigManager() *ConfigManager {
	homeDir, _ := os.UserHomeDir()
	configPath := filepath.Join(homeDir, ".eos", "wazuh-version-config.json")
	
	return &ConfigManager{
		configPath: configPath,
	}
}

// LoadConfig loads the version configuration
func (cm *ConfigManager) LoadConfig(rc *eos_io.RuntimeContext) (*VersionConfig, error) {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Create config directory if it doesn't exist
	if err := os.MkdirAll(filepath.Dir(cm.configPath), 0755); err != nil {
		return nil, fmt.Errorf("failed to create config directory: %w", err)
	}
	
	// If config doesn't exist, create default
	if _, err := os.Stat(cm.configPath); os.IsNotExist(err) {
		logger.Info("Creating default Wazuh version configuration", 
			zap.String("path", cm.configPath))
		
		defaultConfig := DefaultVersionConfig()
		if err := cm.SaveConfig(rc, defaultConfig); err != nil {
			return nil, fmt.Errorf("failed to save default config: %w", err)
		}
		return defaultConfig, nil
	}
	
	// Load existing config
	data, err := os.ReadFile(cm.configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}
	
	var config VersionConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}
	
	// Validate and set defaults for missing fields
	cm.validateAndSetDefaults(&config)
	
	logger.Debug("Loaded Wazuh version configuration",
		zap.String("update_policy", string(config.UpdatePolicy)),
		zap.Bool("auto_update", config.AutoUpdate),
		zap.String("current_version", config.CurrentVersion))
	
	return &config, nil
}

// SaveConfig saves the version configuration
func (cm *ConfigManager) SaveConfig(rc *eos_io.RuntimeContext, config *VersionConfig) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Validate config before saving
	if err := cm.validateConfig(config); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}
	
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}
	
	if err := os.WriteFile(cm.configPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}
	
	logger.Info("Saved Wazuh version configuration", zap.String("path", cm.configPath))
	return nil
}

// UpdateCurrentVersion updates the currently installed version in config
func (cm *ConfigManager) UpdateCurrentVersion(rc *eos_io.RuntimeContext, version string) error {
	config, err := cm.LoadConfig(rc)
	if err != nil {
		return err
	}
	
	config.CurrentVersion = version
	config.LastUpdated = time.Now()
	
	return cm.SaveConfig(rc, config)
}

// ShouldUpdate determines if an update should be performed based on policy
func (cm *ConfigManager) ShouldUpdate(rc *eos_io.RuntimeContext, currentVersion, availableVersion string, manager *Manager) (bool, string, error) {
	config, err := cm.LoadConfig(rc)
	if err != nil {
		return false, "", err
	}
	
	// If version is pinned, don't update
	if config.PinnedVersion != "" {
		if config.PinnedVersion != availableVersion {
			return false, fmt.Sprintf("version pinned to %s", config.PinnedVersion), nil
		}
	}
	
	// Check version constraints
	if config.MinimumVersion != "" {
		if manager.CompareVersions(availableVersion, config.MinimumVersion) < 0 {
			return false, fmt.Sprintf("version %s is below minimum %s", availableVersion, config.MinimumVersion), nil
		}
	}
	
	if config.MaximumVersion != "" {
		if manager.CompareVersions(availableVersion, config.MaximumVersion) > 0 {
			return false, fmt.Sprintf("version %s is above maximum %s", availableVersion, config.MaximumVersion), nil
		}
	}
	
	// Check if already up to date
	if manager.CompareVersions(availableVersion, currentVersion) <= 0 {
		return false, "already up to date", nil
	}
	
	// Check update policy
	switch config.UpdatePolicy {
	case UpdatePolicyManual:
		return false, "manual update policy - updates disabled", nil
		
	case UpdatePolicyPatch:
		if !cm.isPatchUpdate(currentVersion, availableVersion) {
			return false, "only patch updates allowed", nil
		}
		
	case UpdatePolicyMinor:
		if !cm.isMinorOrPatchUpdate(currentVersion, availableVersion) {
			return false, "only minor and patch updates allowed", nil
		}
		
	case UpdatePolicyMajor:
		// Allow all updates
		
	case UpdatePolicyLatest:
		// Always update to latest
		
	default:
		return false, fmt.Sprintf("unknown update policy: %s", config.UpdatePolicy), nil
	}
	
	// Check if we're in maintenance window (if auto-update is enabled)
	if config.AutoUpdate && config.MaintenanceWindow != nil {
		if !cm.isInMaintenanceWindow(config.MaintenanceWindow) {
			return false, "outside maintenance window", nil
		}
	}
	
	// If we reach here, update is allowed
	reason := fmt.Sprintf("update from %s to %s allowed by policy %s", 
		currentVersion, availableVersion, config.UpdatePolicy)
	
	return true, reason, nil
}

// Helper functions

func (cm *ConfigManager) validateConfig(config *VersionConfig) error {
	validPolicies := []UpdatePolicy{
		UpdatePolicyManual, UpdatePolicyPatch, UpdatePolicyMinor, 
		UpdatePolicyMajor, UpdatePolicyLatest,
	}
	
	validPolicy := false
	for _, policy := range validPolicies {
		if config.UpdatePolicy == policy {
			validPolicy = true
			break
		}
	}
	
	if !validPolicy {
		return fmt.Errorf("invalid update policy: %s", config.UpdatePolicy)
	}
	
	if config.MaintenanceWindow != nil {
		if config.MaintenanceWindow.StartHour < 0 || config.MaintenanceWindow.StartHour > 23 {
			return fmt.Errorf("invalid start hour: %d", config.MaintenanceWindow.StartHour)
		}
		if config.MaintenanceWindow.EndHour < 0 || config.MaintenanceWindow.EndHour > 23 {
			return fmt.Errorf("invalid end hour: %d", config.MaintenanceWindow.EndHour)
		}
	}
	
	return nil
}

func (cm *ConfigManager) validateAndSetDefaults(config *VersionConfig) {
	if config.UpdatePolicy == "" {
		config.UpdatePolicy = UpdatePolicyPatch
	}
	if config.CacheTimeout == 0 {
		config.CacheTimeout = 1 * time.Hour
	}
	if config.MaintenanceWindow == nil {
		config.MaintenanceWindow = &TimeWindow{
			StartHour: 2,
			EndHour:   4,
			Days:      []int{0, 6},
			Timezone:  "UTC",
		}
	}
}

func (cm *ConfigManager) isPatchUpdate(current, available string) bool {
	currentParts := cm.parseVersion(current)
	availableParts := cm.parseVersion(available)
	
	if len(currentParts) < 3 || len(availableParts) < 3 {
		return false
	}
	
	// Same major and minor, different patch
	return currentParts[0] == availableParts[0] && 
		   currentParts[1] == availableParts[1] && 
		   currentParts[2] != availableParts[2]
}

func (cm *ConfigManager) isMinorOrPatchUpdate(current, available string) bool {
	currentParts := cm.parseVersion(current)
	availableParts := cm.parseVersion(available)
	
	if len(currentParts) < 3 || len(availableParts) < 3 {
		return false
	}
	
	// Same major, different minor or patch
	return currentParts[0] == availableParts[0]
}

func (cm *ConfigManager) parseVersion(version string) []string {
	// Remove 'v' prefix if present
	if len(version) > 0 && version[0] == 'v' {
		version = version[1:]
	}
	return strings.Split(version, ".")
}

func (cm *ConfigManager) isInMaintenanceWindow(window *TimeWindow) bool {
	now := time.Now()
	
	// Parse timezone
	loc, err := time.LoadLocation(window.Timezone)
	if err != nil {
		loc = time.UTC
	}
	
	nowInTZ := now.In(loc)
	
	// Check if current day is in allowed days
	currentDay := int(nowInTZ.Weekday())
	dayAllowed := false
	for _, day := range window.Days {
		if day == currentDay {
			dayAllowed = true
			break
		}
	}
	
	if !dayAllowed {
		return false
	}
	
	// Check if current hour is in allowed window
	currentHour := nowInTZ.Hour()
	
	if window.StartHour <= window.EndHour {
		// Same day window (e.g., 2 AM to 4 AM)
		return currentHour >= window.StartHour && currentHour < window.EndHour
	} else {
		// Cross-midnight window (e.g., 22:00 to 02:00)
		return currentHour >= window.StartHour || currentHour < window.EndHour
	}
}
