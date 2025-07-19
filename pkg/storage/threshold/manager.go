// pkg/storage/threshold/manager.go

package threshold

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/environment"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Manager handles storage threshold management and action determination
type Manager struct {
	config Config
	env    *environment.Environment
	rc     *eos_io.RuntimeContext
}

// Config holds threshold configuration values
type Config struct {
	Warning   float64
	Compress  float64
	Cleanup   float64
	Degraded  float64
	Emergency float64
	Critical  float64
}

// Action represents a storage management action
type Action string

const (
	ActionNone       Action = "none"
	ActionMonitor    Action = "monitor"
	ActionCompress   Action = "compress"
	ActionCleanup    Action = "cleanup"
	ActionDegrade    Action = "degrade"
	ActionEmergency  Action = "emergency"
	ActionCritical   Action = "critical"
)

// NewManager creates a new threshold manager
func NewManager(rc *eos_io.RuntimeContext, env *environment.Environment) *Manager {
	profile := env.GetStorageProfile()
	
	return &Manager{
		config: Config{
			Warning:   profile.DefaultThresholds.Warning,
			Compress:  profile.DefaultThresholds.Compress,
			Cleanup:   profile.DefaultThresholds.Cleanup,
			Degraded:  profile.DefaultThresholds.Degraded,
			Emergency: profile.DefaultThresholds.Emergency,
			Critical:  profile.DefaultThresholds.Critical,
		},
		env: env,
		rc:  rc,
	}
}

// LoadForEnvironment returns threshold configuration based on environment
func LoadForEnvironment(env *environment.Environment) Config {
	profile := env.GetStorageProfile()
	return Config{
		Warning:   profile.DefaultThresholds.Warning,
		Compress:  profile.DefaultThresholds.Compress,
		Cleanup:   profile.DefaultThresholds.Cleanup,
		Degraded:  profile.DefaultThresholds.Degraded,
		Emergency: profile.DefaultThresholds.Emergency,
		Critical:  profile.DefaultThresholds.Critical,
	}
}

// DetermineActions determines what actions to take based on usage percentage
func (m *Manager) DetermineActions(usagePercent float64) []Action {
	logger := otelzap.Ctx(m.rc.Ctx)
	var actions []Action
	
	logger.Debug("Determining actions for usage",
		zap.Float64("usage_percent", usagePercent),
		zap.Float64("warning_threshold", m.config.Warning),
		zap.Float64("critical_threshold", m.config.Critical))
	
	switch {
	case usagePercent >= m.config.Critical:
		actions = append(actions, ActionCritical, ActionEmergency)
		logger.Error("Critical storage threshold exceeded",
			zap.Float64("usage", usagePercent),
			zap.Float64("threshold", m.config.Critical))
			
	case usagePercent >= m.config.Emergency:
		actions = append(actions, ActionEmergency)
		logger.Error("Emergency storage threshold exceeded",
			zap.Float64("usage", usagePercent),
			zap.Float64("threshold", m.config.Emergency))
			
	case usagePercent >= m.config.Degraded:
		actions = append(actions, ActionDegrade)
		logger.Warn("Degraded storage threshold exceeded",
			zap.Float64("usage", usagePercent),
			zap.Float64("threshold", m.config.Degraded))
			
	case usagePercent >= m.config.Cleanup:
		actions = append(actions, ActionCleanup)
		logger.Warn("Cleanup storage threshold exceeded",
			zap.Float64("usage", usagePercent),
			zap.Float64("threshold", m.config.Cleanup))
			
	case usagePercent >= m.config.Compress:
		actions = append(actions, ActionCompress)
		logger.Info("Compress storage threshold exceeded",
			zap.Float64("usage", usagePercent),
			zap.Float64("threshold", m.config.Compress))
			
	case usagePercent >= m.config.Warning:
		actions = append(actions, ActionMonitor)
		logger.Info("Warning storage threshold exceeded",
			zap.Float64("usage", usagePercent),
			zap.Float64("threshold", m.config.Warning))
			
	default:
		actions = append(actions, ActionNone)
		logger.Debug("Storage usage within acceptable range",
			zap.Float64("usage", usagePercent))
	}
	
	return actions
}

// GetActionDescription returns a human-readable description of an action
func GetActionDescription(action Action) string {
	descriptions := map[Action]string{
		ActionNone:      "No action required",
		ActionMonitor:   "Enhanced monitoring activated",
		ActionCompress:  "Compressing logs and temporary files",
		ActionCleanup:   "Cleaning up expendable data",
		ActionDegrade:   "Degrading non-critical services",
		ActionEmergency: "Emergency cleanup mode activated",
		ActionCritical:  "Critical storage failure - immediate action required",
	}
	
	if desc, ok := descriptions[action]; ok {
		return desc
	}
	return fmt.Sprintf("Unknown action: %s", action)
}

// GetConfig returns the current threshold configuration
func (m *Manager) GetConfig() Config {
	return m.config
}

// UpdateConfig updates the threshold configuration
func (m *Manager) UpdateConfig(config Config) error {
	logger := otelzap.Ctx(m.rc.Ctx)
	
	// Validate thresholds are in ascending order
	if config.Warning >= config.Compress ||
		config.Compress >= config.Cleanup ||
		config.Cleanup >= config.Degraded ||
		config.Degraded >= config.Emergency ||
		config.Emergency >= config.Critical {
		return fmt.Errorf("thresholds must be in ascending order: warning < compress < cleanup < degraded < emergency < critical")
	}
	
	// Validate thresholds are reasonable
	if config.Warning < 0 || config.Critical > 100 {
		return fmt.Errorf("thresholds must be between 0 and 100")
	}
	
	m.config = config
	
	logger.Info("Updated threshold configuration",
		zap.Float64("warning", config.Warning),
		zap.Float64("compress", config.Compress),
		zap.Float64("cleanup", config.Cleanup),
		zap.Float64("degraded", config.Degraded),
		zap.Float64("emergency", config.Emergency),
		zap.Float64("critical", config.Critical))
	
	return nil
}