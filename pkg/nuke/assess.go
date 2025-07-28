package nuke

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/state"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// AssessInfrastructure assesses what infrastructure exists and creates a removal plan
func AssessInfrastructure(rc *eos_io.RuntimeContext, config *Config) (*RemovalPlan, error) {
	logger := otelzap.Ctx(rc.Ctx)
	
	// ASSESS - Check current infrastructure state
	logger.Info("Assessing infrastructure for removal",
		zap.Bool("dev_mode", config.DevMode),
		zap.Bool("keep_data", config.KeepData),
		zap.Strings("excluded", config.ExcludeList))

	// Load current state
	tracker, err := loadCurrentState(rc)
	if err != nil {
		return nil, fmt.Errorf("failed to load infrastructure state: %w", err)
	}

	// Build exclusion map for faster lookups
	excluded := make(map[string]bool)
	for _, ex := range config.ExcludeList {
		excluded[ex] = true
	}

	// Add development exclusions if dev mode is enabled
	if config.DevMode {
		devExclusions := getDevExclusions()
		for _, ex := range devExclusions {
			excluded[ex] = true
			config.ExcludeList = append(config.ExcludeList, ex)
		}
		logger.Info("Development mode enabled - preserving development tools")
	}

	// Create removal plan
	plan := &RemovalPlan{
		Components:    filterComponents(tracker.Components, excluded),
		Services:      getRemovableServices(excluded),
		Directories:   getRemovableDirectories(excluded, config.KeepData),
		ExcludedItems: config.ExcludeList,
		DevModeActive: config.DevMode,
		DataPreserved: config.KeepData,
	}

	logger.Info("Infrastructure assessment completed",
		zap.Int("components_to_remove", len(plan.Components)),
		zap.Int("services_to_remove", len(plan.Services)),
		zap.Int("directories_to_remove", len(plan.Directories)),
		zap.Int("excluded_items", len(plan.ExcludedItems)))

	return plan, nil
}

// loadCurrentState loads the current infrastructure state
func loadCurrentState(rc *eos_io.RuntimeContext) (*state.StateTracker, error) {
	logger := otelzap.Ctx(rc.Ctx)

	tracker, err := state.Load(rc)
	if err != nil {
		logger.Warn("Failed to load state file, scanning for components", zap.Error(err))
		tracker = state.New()
		if err := tracker.GatherInBand(rc); err != nil {
			logger.Warn("Failed to gather in-band state", zap.Error(err))
		}
	}

	return tracker, nil
}

// getDevExclusions returns the list of components to exclude in development mode
func getDevExclusions() []string {
	return []string{
		"code-server",
		"wazuh-agent",
		"prometheus",
		"prometheus-node-exporter",
		"docker",
		"eos",
		"git",
		"golang",
		"github-cli",
		"tailscale",
		"tailscaled",
		"golangci-lint",
	}
}

// filterComponents filters components based on exclusion list
func filterComponents(components []state.Component, excluded map[string]bool) []state.Component {
	var filtered []state.Component
	for _, comp := range components {
		if !excluded[comp.Name] && !excluded[string(comp.Type)] {
			filtered = append(filtered, comp)
		}
	}
	return filtered
}

// getRemovableServices returns the list of services that can be removed
func getRemovableServices(excluded map[string]bool) []ServiceConfig {
	allServices := []ServiceConfig{
		{Name: "osqueryd", Component: "osquery", Required: false},
		{Name: "nomad", Component: "nomad", Required: false},
		{Name: "consul", Component: "consul", Required: false},
		{Name: "vault", Component: "vault", Required: false},
		{Name: "boundary", Component: "boundary", Required: false},
		{Name: "salt-minion", Component: "salt", Required: false},
		{Name: "salt-master", Component: "salt", Required: false},
		{Name: "docker", Component: "docker", Required: false},
		{Name: "eos-storage-monitor", Component: "eos", Required: false},
		{Name: "fail2ban", Component: "fail2ban", Required: false},
		{Name: "trivy", Component: "trivy", Required: false},
		{Name: "wazuh-agent", Component: "wazuh-agent", Required: false},
		{Name: "prometheus", Component: "prometheus", Required: false},
		{Name: "prometheus-node-exporter", Component: "prometheus-node-exporter", Required: false},
		{Name: "grafana-server", Component: "grafana", Required: false},
		{Name: "nginx", Component: "nginx", Required: false},
		{Name: "glances", Component: "glances", Required: false},
		{Name: "code-server@*", Component: "code-server", Required: false},
		{Name: "tailscale", Component: "tailscale", Required: false},
		{Name: "tailscaled", Component: "tailscaled", Required: false},
	}

	var removable []ServiceConfig
	for _, svc := range allServices {
		if !excluded[svc.Component] && !excluded[svc.Name] {
			removable = append(removable, svc)
		}
	}

	return removable
}

// getRemovableDirectories returns the list of directories that can be removed
func getRemovableDirectories(excluded map[string]bool, keepData bool) []DirectoryConfig {
	allDirectories := []DirectoryConfig{
		{Path: "/srv/salt", Component: "salt", IsData: false, Description: "Salt states directory"},
		{Path: "/srv/pillar", Component: "salt", IsData: false, Description: "Salt pillar directory"},
		{Path: "/etc/salt", Component: "salt", IsData: false, Description: "Salt configuration directory"},
		{Path: "/var/log/salt", Component: "salt", IsData: true, Description: "Salt log directory"},
		{Path: "/var/cache/salt", Component: "salt", IsData: true, Description: "Salt cache directory"},
		{Path: "/opt/vault", Component: "vault", IsData: false, Description: "Vault binary directory"},
		{Path: "/opt/vault/data", Component: "vault", IsData: true, Description: "Vault data directory"},
		{Path: "/etc/vault.d", Component: "vault", IsData: false, Description: "Vault configuration directory"},
		{Path: "/opt/nomad", Component: "nomad", IsData: false, Description: "Nomad binary directory"},
		{Path: "/opt/nomad/data", Component: "nomad", IsData: true, Description: "Nomad data directory"},
		{Path: "/etc/nomad.d", Component: "nomad", IsData: false, Description: "Nomad configuration directory"},
		{Path: "/opt/consul", Component: "consul", IsData: false, Description: "Consul binary directory"},
		{Path: "/opt/consul/data", Component: "consul", IsData: true, Description: "Consul data directory"},
		{Path: "/etc/consul.d", Component: "consul", IsData: false, Description: "Consul configuration directory"},
		{Path: "/var/lib/eos", Component: "eos", IsData: false, Description: "Eos state directory"},
	}

	var removable []DirectoryConfig
	for _, dir := range allDirectories {
		// Skip if component is excluded
		if excluded[dir.Component] {
			continue
		}
		
		// Skip data directories if keepData is true
		if dir.IsData && keepData {
			continue
		}

		removable = append(removable, dir)
	}

	return removable
}