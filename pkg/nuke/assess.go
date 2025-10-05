package nuke

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/boundary"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/docker"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/osquery"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/packer"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/state"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/terraform"
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

	// Create removal plan using dynamic discovery
	plan := &RemovalPlan{
		Components:    filterComponents(tracker.Components, excluded),
		Services:      getRemovableServicesDynamic(excluded),
		Directories:   getRemovableDirectoriesDynamic(excluded, config.KeepData),
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
		if err := tracker.GatherOutOfBand(rc); err != nil {
			logger.Warn("Failed to gather in-band state", zap.Error(err))
		}
	}

	return tracker, nil
}

// getDevExclusions returns the list of components to exclude in development mode
// When --dev flag is used:
// 1. All tools listed here are preserved (not removed)
// 2. All /opt/* directories are preserved (see executePhase5DirectoriesAndFiles)
// 3. This protects development environments from accidental destruction
// The preserved tools include:
// - Development tools: code-server, git, golang, github-cli, golangci-lint
// - Container runtime: docker (needed for development)
// - Remote access: tailscale/tailscaled
// - Monitoring: prometheus, prometheus-node-exporter, wazuh-agent
// - Eos itself (to continue using the tool)
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

// The old hardcoded functions have been replaced by dynamic discovery.
// Keeping these here for reference only - they are no longer used.
// TODO: Remove these functions in a future cleanup once we're confident in the dynamic discovery.

// getRemovableServicesDynamic dynamically discovers services from all components
func getRemovableServicesDynamic(excluded map[string]bool) []ServiceConfig {
	// Use a map to prevent duplicates
	serviceMap := make(map[string]ServiceConfig)

	// Add services from components with removal functions
	for _, svc := range osquery.GetOsqueryServices() {
		serviceMap[svc.Name] = ServiceConfig{
			Name:      svc.Name,
			Component: svc.Component,
			Required:  svc.Required,
		}
	}

	for _, svc := range boundary.GetBoundaryServices() {
		serviceMap[svc.Name] = ServiceConfig{
			Name:      svc.Name,
			Component: svc.Component,
			Required:  svc.Required,
		}
	}

	for _, svc := range docker.GetDockerServices() {
		serviceMap[svc.Name] = ServiceConfig{
			Name:      svc.Name,
			Component: svc.Component,
			Required:  svc.Required,
		}
	}

	// Eos services removed - no longer needed
	// for _, svc := range eos.GetEosServices() {
	// 	serviceMap[svc.Name] = ServiceConfig{
	// 		Name:      svc.Name,
	// 		Component: svc.Component,
	// 		Required:  svc.Required,
	// 	}
	// }

	// Add hardcoded services that already have proper lifecycle managers
	hardcodedServices := []ServiceConfig{
		{Name: "nomad", Component: "nomad", Required: false},
		{Name: "consul", Component: "consul", Required: false},
		{Name: "vault", Component: "vault", Required: false},
		{Name: "-minion", Component: "", Required: false},
		{Name: "-master", Component: "", Required: false},
		{Name: "hecate-caddy", Component: "hecate", Required: false},
		{Name: "hecate-authentik", Component: "hecate", Required: false},
		{Name: "hecate-redis", Component: "hecate", Required: false},
		{Name: "hecate-postgres", Component: "hecate", Required: false},
	}

	for _, svc := range hardcodedServices {
		serviceMap[svc.Name] = svc
	}

	// Skip adding services from GetAdditionalServicesConfigs here
	// because they're already handled in Phase 2 by removeAdditionalServices
	// This prevents duplicate service removal attempts

	// Convert map to slice and filter excluded services
	var removable []ServiceConfig
	for _, svc := range serviceMap {
		if !excluded[svc.Component] && !excluded[svc.Name] {
			removable = append(removable, svc)
		}
	}

	return removable
}

// getRemovableDirectoriesDynamic dynamically discovers directories from all components
func getRemovableDirectoriesDynamic(excluded map[string]bool, keepData bool) []DirectoryConfig {
	var allDirectories []DirectoryConfig

	// Add directories from components with removal functions
	for _, dir := range osquery.GetOsqueryDirectories() {
		allDirectories = append(allDirectories, DirectoryConfig{
			Path:        dir.Path,
			Component:   dir.Component,
			IsData:      dir.IsData,
			Description: dir.Description,
		})
	}

	for _, dir := range boundary.GetBoundaryDirectories() {
		allDirectories = append(allDirectories, DirectoryConfig{
			Path:        dir.Path,
			Component:   dir.Component,
			IsData:      dir.IsData,
			Description: dir.Description,
		})
	}

	for _, dir := range docker.GetDockerDirectories() {
		allDirectories = append(allDirectories, DirectoryConfig{
			Path:        dir.Path,
			Component:   dir.Component,
			IsData:      dir.IsData,
			Description: dir.Description,
		})
	}

	for _, dir := range terraform.GetTerraformDirectories() {
		allDirectories = append(allDirectories, DirectoryConfig{
			Path:        dir.Path,
			Component:   dir.Component,
			IsData:      dir.IsData,
			Description: dir.Description,
		})
	}

	for _, dir := range packer.GetPackerDirectories() {
		allDirectories = append(allDirectories, DirectoryConfig{
			Path:        dir.Path,
			Component:   dir.Component,
			IsData:      dir.IsData,
			Description: dir.Description,
		})
	}

	// Eos directories removed - no longer needed
	// for _, dir := range eos.GetEosDirectories() {
	// 	allDirectories = append(allDirectories, DirectoryConfig{
	// 		Path:        dir.Path,
	// 		Component:   dir.Component,
	// 		IsData:      dir.IsData,
	// 		Description: dir.Description,
	// 	})
	// }

	// Add hardcoded directories for components with proper lifecycle managers
	// These will be removed once all components implement the lifecycle interface
	allDirectories = append(allDirectories, []DirectoryConfig{
		{Path: "/srv/", Component: "", IsData: false, Description: " states directory"},
		{Path: "/srv/", Component: "", IsData: false, Description: "  directory"},
		{Path: "/etc/", Component: "", IsData: false, Description: " configuration directory"},
		{Path: "/var/log/", Component: "", IsData: true, Description: " log directory"},
		{Path: "/var/cache/", Component: "", IsData: true, Description: " cache directory"},
		{Path: "/opt/vault", Component: "vault", IsData: false, Description: "Vault binary directory"},
		{Path: "/opt/vault/data", Component: "vault", IsData: true, Description: "Vault data directory"},
		{Path: "/etc/vault.d", Component: "vault", IsData: false, Description: "Vault configuration directory"},
		{Path: "/opt/nomad", Component: "nomad", IsData: false, Description: "Nomad binary directory"},
		{Path: "/opt/nomad/data", Component: "nomad", IsData: true, Description: "Nomad data directory"},
		{Path: "/etc/nomad.d", Component: "nomad", IsData: false, Description: "Nomad configuration directory"},
		{Path: "/opt/consul", Component: "consul", IsData: false, Description: "Consul binary directory"},
		{Path: "/opt/consul/data", Component: "consul", IsData: true, Description: "Consul data directory"},
		{Path: "/etc/consul.d", Component: "consul", IsData: false, Description: "Consul configuration directory"},
	}...)

	// Filter directories
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
