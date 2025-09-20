package nuke

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/state"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// AssessInfrastructureV2 demonstrates improved Go patterns using interfaces
func AssessInfrastructureV2(rc *eos_io.RuntimeContext, config *Config) (*RemovalPlan, error) {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Assessing infrastructure for removal (v2)",
		zap.Bool("dev_mode", config.DevMode),
		zap.Bool("keep_data", config.KeepData),
		zap.Strings("excluded", config.ExcludeList))

	// Load current state with proper error wrapping
	tracker, err := loadCurrentStateV2(rc)
	if err != nil {
		return nil, fmt.Errorf("failed to load infrastructure state: %w", err)
	}

	// Build exclusion map using make with capacity hint for performance
	excluded := make(map[string]bool, len(config.ExcludeList))
	for _, ex := range config.ExcludeList {
		excluded[ex] = true
	}

	// Create assessment engine and register providers
	engine := NewAssessmentEngine()
	registerAllProviders(engine)

	// Create removal plan using the interface-based approach
	plan := &RemovalPlan{
		Components:    filterComponentsV2(tracker.Components, excluded),
		Services:      engine.GetAllServices(excluded),
		Directories:   engine.GetAllDirectories(excluded, config.KeepData),
		ExcludedItems: config.ExcludeList,
		DevModeActive: config.DevMode,
		DataPreserved: config.KeepData,
	}

	// Apply development exclusions if in dev mode
	if config.DevMode {
		plan = applyDevExclusions(plan, logger)
	}

	logAssessmentResults(plan, logger)
	return plan, nil
}

// loadCurrentStateV2 demonstrates proper error handling patterns
func loadCurrentStateV2(rc *eos_io.RuntimeContext) (*state.StateTracker, error) {
	logger := otelzap.Ctx(rc.Ctx)

	tracker, err := state.Load(rc)
	if err != nil {
		logger.Warn("Failed to load state file, scanning for components", zap.Error(err))

		// Create new tracker and attempt in-band gathering
		tracker = state.New()
		if err := tracker.GatherOutOfBand(rc); err != nil {
			// Wrap both errors for better context
			return nil, fmt.Errorf("failed to load state (%w) and gather out-of-band state (%w)",
				err, err)
		}

		logger.Info("Successfully gathered out-of-band state as fallback")
	}

	return tracker, nil
}

// applyDevExclusions demonstrates functional programming patterns
func applyDevExclusions(plan *RemovalPlan, logger otelzap.LoggerWithCtx) *RemovalPlan {
	devExclusions := getDevExclusionsV2()

	// Convert to map for efficient lookup
	excludedMap := make(map[string]bool)
	for _, item := range plan.ExcludedItems {
		excludedMap[item] = true
	}

	// Add dev exclusions that aren't already present
	for exclusion := range devExclusions {
		if !excludedMap[exclusion] {
			plan.ExcludedItems = append(plan.ExcludedItems, exclusion)
		}
	}

	logger.Info("Development mode enabled - preserving development tools",
		zap.Int("dev_exclusions_count", len(devExclusions)))
	return plan
}

// getDevExclusionsV2 demonstrates slice initialization best practices
func getDevExclusionsV2() map[string]bool {
	// Pre-allocate slice with known capacity for performance
	exclusions := make(map[string]bool)
	exclusions["code-server"] = true
	exclusions["wazuh-agent"] = true
	exclusions["prometheus"] = true
	exclusions["prometheus-node-exporter"] = true
	exclusions["docker"] = true
	exclusions["eos"] = true
	exclusions["git"] = true
	exclusions["golang"] = true
	exclusions["github-cli"] = true
	exclusions["tailscale"] = true
	exclusions["tailscaled"] = true
	exclusions["golangci-lint"] = true
	return exclusions
}

// filterComponentsV2 demonstrates improved filtering with early returns
func filterComponentsV2(components []state.Component, excluded map[string]bool) []state.Component {
	if len(components) == 0 {
		return nil // Return nil for empty slice (Go idiom)
	}

	// Pre-allocate with estimated capacity
	filtered := make([]state.Component, 0, len(components)/2)

	for _, comp := range components {
		// Early continue for excluded items
		if excluded[comp.Name] || excluded[string(comp.Type)] {
			continue
		}
		filtered = append(filtered, comp)
	}

	return filtered
}

// logAssessmentResults demonstrates structured logging best practices
func logAssessmentResults(plan *RemovalPlan, logger otelzap.LoggerWithCtx) {
	logger.Info("Infrastructure assessment completed",
		zap.Int("components_to_remove", len(plan.Components)),
		zap.Int("services_to_remove", len(plan.Services)),
		zap.Int("directories_to_remove", len(plan.Directories)),
		zap.Int("excluded_items", len(plan.ExcludedItems)),
		zap.Bool("dev_mode_active", plan.DevModeActive),
		zap.Bool("data_preserved", plan.DataPreserved))
}

// registerAllProviders demonstrates the registry pattern
func registerAllProviders(engine *AssessmentEngine) {
	// In a real implementation, you would register actual providers here
	// This demonstrates the pattern without requiring all the imports

	// Example of how you would register providers:
	// engine.RegisterProvider(osquery.NewProvider())
	// engine.RegisterProvider(boundary.NewProvider())
	// engine.RegisterProvider(docker.NewProvider())

	// For now, we'll use a mock provider to demonstrate the pattern
	engine.RegisterProvider(&mockProvider{})
}

// mockProvider demonstrates interface implementation
type mockProvider struct{}

func (m *mockProvider) GetServices() []ServiceConfig {
	return []ServiceConfig{
		{Name: "example-service", Component: "example", Required: false},
	}
}

func (m *mockProvider) GetDirectories() []DirectoryConfig {
	return []DirectoryConfig{
		{Path: "/opt/example", Component: "example", IsData: false, Description: "Example directory"},
	}
}

func (m *mockProvider) GetComponentName() string {
	return "example"
}
