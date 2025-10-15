// pkg/vault/phase9e_enable_tracking.go

package vault

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/hashicorp/vault/api"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// PhaseEnableTracking enables Vault activity tracking and client count reporting
//
// Activity tracking provides visibility into:
// - Active clients (entities and non-entity tokens)
// - Monthly active client counts
// - Authentication method usage
// - Namespace activity (if using Vault Enterprise)
//
// This phase should be called during initial Vault setup, after authentication
// methods are configured but before production use begins.
func PhaseEnableTracking(rc *eos_io.RuntimeContext, client *api.Client) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info(" [Phase 9e] Enabling Vault activity tracking")

	// Get privileged client
	logger.Info(" Requesting privileged Vault client")
	privilegedClient, err := GetRootClient(rc)
	if err != nil {
		logger.Error(" Failed to get privileged Vault client", zap.Error(err))
		return fmt.Errorf("failed to get privileged client: %w", err)
	}

	// Log client readiness
	if token := privilegedClient.Token(); token != "" {
		logger.Info(" Privileged Vault client ready")
	} else {
		logger.Error(" Privileged client has no token set")
		return fmt.Errorf("privileged client has no token")
	}

	// Enable activity tracking
	if err := EnableActivityTracking(rc, privilegedClient); err != nil {
		logger.Error(" Failed to enable activity tracking", zap.Error(err))
		return fmt.Errorf("failed to enable activity tracking: %w", err)
	}

	// Verify tracking is enabled
	if err := VerifyActivityTracking(rc, privilegedClient); err != nil {
		logger.Error(" Failed to verify activity tracking", zap.Error(err))
		return fmt.Errorf("failed to verify activity tracking: %w", err)
	}

	logger.Info(" [Phase 9e] Activity tracking enabled successfully")
	logger.Info("terminal prompt: Activity tracking is now collecting client usage data")
	logger.Info("terminal prompt: View activity reports: vault read sys/internal/counters/activity/monthly")

	return nil
}

// EnableActivityTracking enables Vault's activity log and client count tracking
//
// The activity tracking system:
// - Records active client usage (entities and tokens)
// - Generates monthly activity reports
// - Tracks authentication method usage
// - Provides insights for capacity planning
//
// By default, activity tracking is disabled in Vault. This function enables it
// and configures appropriate retention settings.
func EnableActivityTracking(rc *eos_io.RuntimeContext, client *api.Client) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info(" Enabling Vault activity tracking")

	// ASSESS: Check current activity tracking configuration
	logger.Info(" Checking current activity tracking status")
	currentConfig, err := GetActivityTrackingConfig(rc, client)
	if err != nil {
		logger.Warn(" Could not retrieve current activity tracking config",
			zap.Error(err))
		// Continue anyway - might not be readable before enabling
	} else if currentConfig != nil && currentConfig.Enabled {
		logger.Info(" Activity tracking is already enabled",
			zap.String("retention_months", fmt.Sprintf("%d", currentConfig.RetentionMonths)))
		return nil
	}

	// INTERVENE: Enable activity tracking via sys/internal/counters/config
	logger.Info(" Enabling activity tracking via API")

	config := map[string]interface{}{
		"enabled":          "enable",
		"retention_months": 24, // Store 24 months of activity data
	}

	// Write to the activity config endpoint
	_, err = client.Logical().Write("sys/internal/counters/config", config)
	if err != nil {
		logger.Error(" Failed to enable activity tracking via API",
			zap.Error(err))
		return fmt.Errorf("failed to enable activity tracking: %w", err)
	}

	logger.Info(" Activity tracking enabled successfully",
		zap.Int("retention_months", 24))

	// EVALUATE: Verify tracking was enabled
	logger.Info(" Verifying activity tracking configuration")
	verifiedConfig, err := GetActivityTrackingConfig(rc, client)
	if err != nil {
		logger.Error(" Failed to verify activity tracking config", zap.Error(err))
		return fmt.Errorf("failed to verify activity tracking: %w", err)
	}

	if verifiedConfig == nil || !verifiedConfig.Enabled {
		logger.Error(" Activity tracking not enabled after configuration")
		return fmt.Errorf("activity tracking verification failed")
	}

	logger.Info(" Activity tracking verified and operational",
		zap.Bool("enabled", verifiedConfig.Enabled),
		zap.Int("retention_months", verifiedConfig.RetentionMonths))

	logger.Info("terminal prompt: Activity tracking has been enabled")
	logger.Info("terminal prompt: Client count data will be available after 24 hours of operation")
	logger.Info("terminal prompt: View configuration: vault read sys/internal/counters/config")

	return nil
}

// ActivityTrackingConfig represents the Vault activity tracking configuration
type ActivityTrackingConfig struct {
	Enabled         bool   `json:"enabled"`
	RetentionMonths int    `json:"retention_months"`
	DefaultReportMonths int `json:"default_report_months"`
}

// GetActivityTrackingConfig retrieves the current activity tracking configuration
func GetActivityTrackingConfig(rc *eos_io.RuntimeContext, client *api.Client) (*ActivityTrackingConfig, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug(" Reading activity tracking configuration")

	// Read from sys/internal/counters/config
	secret, err := client.Logical().Read("sys/internal/counters/config")
	if err != nil {
		logger.Debug(" Failed to read activity tracking config", zap.Error(err))
		return nil, fmt.Errorf("failed to read activity tracking config: %w", err)
	}

	if secret == nil || secret.Data == nil {
		logger.Debug(" No activity tracking config found")
		return nil, nil
	}

	config := &ActivityTrackingConfig{}

	// Parse enabled status
	if enabled, ok := secret.Data["enabled"].(string); ok {
		config.Enabled = (enabled == "enable" || enabled == "default-enable")
	} else if enabledBool, ok := secret.Data["enabled"].(bool); ok {
		config.Enabled = enabledBool
	}

	// Parse retention months
	if retention, ok := secret.Data["retention_months"].(float64); ok {
		config.RetentionMonths = int(retention)
	} else if retention, ok := secret.Data["retention_months"].(int); ok {
		config.RetentionMonths = retention
	}

	// Parse default report months
	if defaultMonths, ok := secret.Data["default_report_months"].(float64); ok {
		config.DefaultReportMonths = int(defaultMonths)
	} else if defaultMonths, ok := secret.Data["default_report_months"].(int); ok {
		config.DefaultReportMonths = defaultMonths
	}

	logger.Debug(" Activity tracking config retrieved",
		zap.Bool("enabled", config.Enabled),
		zap.Int("retention_months", config.RetentionMonths),
		zap.Int("default_report_months", config.DefaultReportMonths))

	return config, nil
}

// VerifyActivityTracking verifies that activity tracking is enabled and operational
func VerifyActivityTracking(rc *eos_io.RuntimeContext, client *api.Client) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info(" Verifying activity tracking is operational")

	// ASSESS: Read activity tracking configuration
	config, err := GetActivityTrackingConfig(rc, client)
	if err != nil {
		logger.Error(" Failed to read activity tracking config", zap.Error(err))
		return fmt.Errorf("failed to read activity tracking config: %w", err)
	}

	if config == nil {
		logger.Error(" Activity tracking config is nil")
		return fmt.Errorf("activity tracking config not found")
	}

	if !config.Enabled {
		logger.Error(" Activity tracking is not enabled")
		return fmt.Errorf("activity tracking is disabled")
	}

	logger.Info(" Activity tracking verified as enabled",
		zap.Int("retention_months", config.RetentionMonths))

	// Try to read activity data (may be empty if Vault just started)
	logger.Debug(" Attempting to read activity data")
	secret, err := client.Logical().Read("sys/internal/counters/activity/monthly")
	if err != nil {
		logger.Warn(" Could not read activity data (this is normal for new installations)",
			zap.Error(err))
		// This is not fatal - activity data accumulates over time
	} else if secret != nil {
		logger.Info(" Activity data endpoint is accessible",
			zap.Any("data_keys", getMapKeys(secret.Data)))
	}

	logger.Info(" Activity tracking verification completed")
	return nil
}

// DisableActivityTracking disables Vault activity tracking
//
// CAUTION: Disabling activity tracking will:
// - Stop collecting new client activity data
// - Preserve existing activity logs (based on retention policy)
// - Disable monthly activity reports
func DisableActivityTracking(rc *eos_io.RuntimeContext, client *api.Client) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Warn(" Disabling Vault activity tracking")

	// ASSESS: Check if tracking is currently enabled
	config, err := GetActivityTrackingConfig(rc, client)
	if err != nil {
		logger.Error(" Failed to read activity tracking config", zap.Error(err))
		return fmt.Errorf("failed to read activity tracking config: %w", err)
	}

	if config == nil || !config.Enabled {
		logger.Info(" Activity tracking is already disabled")
		return nil
	}

	// INTERVENE: Disable activity tracking
	logger.Info(" Disabling activity tracking via API")

	disableConfig := map[string]interface{}{
		"enabled": "disable",
	}

	_, err = client.Logical().Write("sys/internal/counters/config", disableConfig)
	if err != nil {
		logger.Error(" Failed to disable activity tracking", zap.Error(err))
		return fmt.Errorf("failed to disable activity tracking: %w", err)
	}

	logger.Info(" Activity tracking disabled successfully")

	// EVALUATE: Verify tracking is disabled
	verifiedConfig, err := GetActivityTrackingConfig(rc, client)
	if err != nil {
		logger.Error(" Failed to verify activity tracking status", zap.Error(err))
		return fmt.Errorf("failed to verify activity tracking status: %w", err)
	}

	if verifiedConfig != nil && verifiedConfig.Enabled {
		logger.Error(" Activity tracking still enabled after disable attempt")
		return fmt.Errorf("activity tracking is still enabled")
	}

	logger.Info(" Activity tracking successfully disabled and verified")

	return nil
}

// GetActivityReport retrieves the monthly activity report
//
// The report includes:
// - Total active clients
// - Entity clients
// - Non-entity clients
// - Breakdown by authentication method
func GetActivityReport(rc *eos_io.RuntimeContext, client *api.Client) (map[string]interface{}, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug(" Retrieving activity report")

	// Read monthly activity data
	secret, err := client.Logical().Read("sys/internal/counters/activity/monthly")
	if err != nil {
		logger.Error(" Failed to read activity report", zap.Error(err))
		return nil, fmt.Errorf("failed to read activity report: %w", err)
	}

	if secret == nil || secret.Data == nil {
		logger.Warn(" No activity data available")
		return nil, fmt.Errorf("no activity data available")
	}

	logger.Debug(" Activity report retrieved",
		zap.Any("data_keys", getMapKeys(secret.Data)))

	return secret.Data, nil
}

// GetCurrentMonthActivity retrieves activity data for the current month
func GetCurrentMonthActivity(rc *eos_io.RuntimeContext, client *api.Client) (map[string]interface{}, error) {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Debug(" Retrieving current month activity")

	// Read current month activity
	secret, err := client.Logical().Read("sys/internal/counters/activity")
	if err != nil {
		logger.Error(" Failed to read current month activity", zap.Error(err))
		return nil, fmt.Errorf("failed to read current month activity: %w", err)
	}

	if secret == nil || secret.Data == nil {
		logger.Warn(" No current month activity data available")
		return nil, fmt.Errorf("no current month activity data available")
	}

	logger.Debug(" Current month activity retrieved",
		zap.Any("data_keys", getMapKeys(secret.Data)))

	return secret.Data, nil
}

// PrintActivityReport displays a formatted activity report to the user
func PrintActivityReport(rc *eos_io.RuntimeContext, report map[string]interface{}) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: === Vault Activity Report ===")
	logger.Info("terminal prompt: ")

	// Extract and display key metrics
	if totalClients, ok := report["total"].(map[string]interface{}); ok {
		if clients, ok := totalClients["clients"].(float64); ok {
			logger.Info(fmt.Sprintf("terminal prompt: Total Active Clients: %.0f", clients))
		}
		if entityClients, ok := totalClients["entity_clients"].(float64); ok {
			logger.Info(fmt.Sprintf("terminal prompt: Entity Clients: %.0f", entityClients))
		}
		if nonEntityClients, ok := totalClients["non_entity_clients"].(float64); ok {
			logger.Info(fmt.Sprintf("terminal prompt: Non-Entity Clients: %.0f", nonEntityClients))
		}
	}

	logger.Info("terminal prompt: ")
	logger.Info("terminal prompt: For detailed breakdown: vault read sys/internal/counters/activity/monthly")
	logger.Info("terminal prompt: ")
}
