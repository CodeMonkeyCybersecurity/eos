package nuke

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/boundary"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/docker"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/osquery"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/packer"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/services"
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

// TODO: MIGRATE SERVICE LIST - This hardcoded list should be built from component lifecycle managers
// FIXME: Each component should register its services, this function should aggregate them
// 
// LIFECYCLE MANAGER STATUS:
// ✅ MIGRATED: nomad -> pkg/nomad/removal.go:RemoveNomadCompletely
// ✅ MIGRATED: consul -> pkg/consul/remove.go:RemoveConsul
// ✅ MIGRATED: vault -> pkg/vault/salt_removal.go:RemoveVaultViaSalt
// ✅ MIGRATED: salt -> pkg/saltstack/removal.go:RemoveSaltCompletely
// ✅ MIGRATED: hecate -> pkg/hecate/removal.go:RemoveHecateCompletely
// ✅ MIGRATED: fail2ban,trivy,wazuh-agent,prometheus,grafana,nginx,glances,code-server,tailscale -> pkg/services/removal.go:RemoveService
// ❌ MISSING: osquery (needs pkg/osquery/removal.go)
// ❌ MISSING: boundary (needs pkg/boundary/removal.go)
// ❌ MISSING: docker (needs pkg/docker/removal.go)
// ❌ MISSING: eos (needs pkg/eos/removal.go)
//
// getRemovableServices returns the list of services that can be removed
func getRemovableServices(excluded map[string]bool) []ServiceConfig {
	allServices := []ServiceConfig{
		{Name: "osqueryd", Component: "osquery", Required: false}, // TODO: MIGRATE - needs pkg/osquery/removal.go
		{Name: "nomad", Component: "nomad", Required: false}, // ✅ MIGRATED
		{Name: "consul", Component: "consul", Required: false}, // ✅ MIGRATED
		{Name: "vault", Component: "vault", Required: false}, // ✅ MIGRATED
		{Name: "boundary", Component: "boundary", Required: false}, // TODO: MIGRATE - needs pkg/boundary/removal.go
		{Name: "salt-minion", Component: "salt", Required: false}, // ✅ MIGRATED
		{Name: "salt-master", Component: "salt", Required: false}, // ✅ MIGRATED
		{Name: "docker", Component: "docker", Required: false}, // TODO: MIGRATE - needs pkg/docker/removal.go
		{Name: "eos-storage-monitor", Component: "eos", Required: false}, // TODO: MIGRATE - needs pkg/eos/removal.go
		{Name: "fail2ban", Component: "fail2ban", Required: false}, // ✅ MIGRATED to pkg/services
		{Name: "trivy", Component: "trivy", Required: false}, // ✅ MIGRATED to pkg/services
		{Name: "wazuh-agent", Component: "wazuh-agent", Required: false}, // ✅ MIGRATED to pkg/services
		{Name: "prometheus", Component: "prometheus", Required: false}, // ✅ MIGRATED to pkg/services
		{Name: "prometheus-node-exporter", Component: "prometheus-node-exporter", Required: false}, // ✅ MIGRATED to pkg/services
		{Name: "grafana-server", Component: "grafana", Required: false}, // ✅ MIGRATED to pkg/services
		{Name: "nginx", Component: "nginx", Required: false}, // ✅ MIGRATED to pkg/services
		{Name: "glances", Component: "glances", Required: false}, // ✅ MIGRATED to pkg/services
		{Name: "code-server@*", Component: "code-server", Required: false}, // ✅ MIGRATED to pkg/services
		{Name: "tailscaled", Component: "tailscale", Required: false}, // ✅ MIGRATED to pkg/services
		{Name: "hecate-caddy", Component: "hecate", Required: false}, // ✅ MIGRATED
		{Name: "hecate-authentik", Component: "hecate", Required: false}, // ✅ MIGRATED
		{Name: "hecate-redis", Component: "hecate", Required: false}, // ✅ MIGRATED
		{Name: "hecate-postgres", Component: "hecate", Required: false}, // ✅ MIGRATED
	}

	var removable []ServiceConfig
	for _, svc := range allServices {
		if !excluded[svc.Component] && !excluded[svc.Name] {
			removable = append(removable, svc)
		}
	}

	return removable
}

// TODO: MIGRATE DIRECTORY LIST - This hardcoded list should be built from component lifecycle managers
// FIXME: Each component should register its directories, this function should aggregate them
//
// DIRECTORY OWNERSHIP ANALYSIS:
// ✅ MIGRATED: salt directories -> pkg/saltstack/removal.go (lines 113-127, 237-253)
// ✅ MIGRATED: vault directories -> pkg/vault/salt_removal.go (lines 116-128) and phase_delete.go
// ✅ MIGRATED: nomad directories -> pkg/nomad/removal.go (lines 100-111, 214-231)
// ✅ MIGRATED: consul directories -> pkg/consul/remove.go (lines 152-169, 200-229)
// ❌ MISSING: eos directories -> need pkg/eos/removal.go
//
// DUPLICATE ISSUE: These directories are handled by both nuke and component managers!
// This creates maintenance burden and potential inconsistencies.
//
// getRemovableDirectories returns the list of directories that can be removed
func getRemovableDirectories(excluded map[string]bool, keepData bool) []DirectoryConfig {
	allDirectories := []DirectoryConfig{
		{Path: "/srv/salt", Component: "salt", IsData: false, Description: "Salt states directory"}, // DUPLICATE: handled in pkg/saltstack/removal.go:113-127
		{Path: "/srv/pillar", Component: "salt", IsData: false, Description: "Salt pillar directory"}, // DUPLICATE: handled in pkg/saltstack/removal.go:113-127
		{Path: "/etc/salt", Component: "salt", IsData: false, Description: "Salt configuration directory"}, // DUPLICATE: handled in pkg/saltstack/removal.go:113-127
		{Path: "/var/log/salt", Component: "salt", IsData: true, Description: "Salt log directory"}, // DUPLICATE: handled in pkg/saltstack/removal.go:113-127
		{Path: "/var/cache/salt", Component: "salt", IsData: true, Description: "Salt cache directory"}, // DUPLICATE: handled in pkg/saltstack/removal.go:113-127
		{Path: "/opt/vault", Component: "vault", IsData: false, Description: "Vault binary directory"}, // DUPLICATE: handled in pkg/vault/salt_removal.go:116-128
		{Path: "/opt/vault/data", Component: "vault", IsData: true, Description: "Vault data directory"}, // DUPLICATE: handled in pkg/vault/salt_removal.go:116-128
		{Path: "/etc/vault.d", Component: "vault", IsData: false, Description: "Vault configuration directory"}, // DUPLICATE: handled in pkg/vault/salt_removal.go:116-128
		{Path: "/opt/nomad", Component: "nomad", IsData: false, Description: "Nomad binary directory"}, // DUPLICATE: handled in pkg/nomad/removal.go:100-111
		{Path: "/opt/nomad/data", Component: "nomad", IsData: true, Description: "Nomad data directory"}, // DUPLICATE: handled in pkg/nomad/removal.go:100-111
		{Path: "/etc/nomad.d", Component: "nomad", IsData: false, Description: "Nomad configuration directory"}, // DUPLICATE: handled in pkg/nomad/removal.go:100-111
		{Path: "/opt/consul", Component: "consul", IsData: false, Description: "Consul binary directory"}, // DUPLICATE: handled in pkg/consul/remove.go:152-169
		{Path: "/opt/consul/data", Component: "consul", IsData: true, Description: "Consul data directory"}, // DUPLICATE: handled in pkg/consul/remove.go:152-169
		{Path: "/etc/consul.d", Component: "consul", IsData: false, Description: "Consul configuration directory"}, // DUPLICATE: handled in pkg/consul/remove.go:152-169
		{Path: "/var/lib/eos", Component: "eos", IsData: false, Description: "Eos state directory"}, // TODO: MIGRATE - needs pkg/eos/removal.go
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

// getRemovableServicesDynamic dynamically discovers services from all components
func getRemovableServicesDynamic(excluded map[string]bool) []ServiceConfig {
	// Get services from components that have explicit removal functions
	var allServices []ServiceConfig
	
	// Add services from components with removal functions
	for _, svc := range osquery.GetOsqueryServices() {
		allServices = append(allServices, ServiceConfig{
			Name:      svc.Name,
			Component: svc.Component,
			Required:  svc.Required,
		})
	}
	
	for _, svc := range boundary.GetBoundaryServices() {
		allServices = append(allServices, ServiceConfig{
			Name:      svc.Name,
			Component: svc.Component,
			Required:  svc.Required,
		})
	}
	
	for _, svc := range docker.GetDockerServices() {
		allServices = append(allServices, ServiceConfig{
			Name:      svc.Name,
			Component: svc.Component,
			Required:  svc.Required,
		})
	}
	
	for _, svc := range eos.GetEosServices() {
		allServices = append(allServices, ServiceConfig{
			Name:      svc.Name,
			Component: svc.Component,
			Required:  svc.Required,
		})
	}
	
	// Add hardcoded services that already have proper lifecycle managers
	allServices = append(allServices, []ServiceConfig{
		{Name: "nomad", Component: "nomad", Required: false},
		{Name: "consul", Component: "consul", Required: false},
		{Name: "vault", Component: "vault", Required: false},
		{Name: "salt-minion", Component: "salt", Required: false},
		{Name: "salt-master", Component: "salt", Required: false},
		{Name: "hecate-caddy", Component: "hecate", Required: false},
		{Name: "hecate-authentik", Component: "hecate", Required: false},
		{Name: "hecate-redis", Component: "hecate", Required: false},
		{Name: "hecate-postgres", Component: "hecate", Required: false},
	}...)
	
	// Add services handled by generic service removal
	for _, svcConfig := range services.GetAdditionalServicesConfigs() {
		allServices = append(allServices, ServiceConfig{
			Name:      svcConfig.Name,
			Component: svcConfig.Name,
			Required:  false,
		})
	}
	
	// Filter excluded services
	var removable []ServiceConfig
	for _, svc := range allServices {
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
	
	for _, dir := range eos.GetEosDirectories() {
		allDirectories = append(allDirectories, DirectoryConfig{
			Path:        dir.Path,
			Component:   dir.Component,
			IsData:      dir.IsData,
			Description: dir.Description,
		})
	}
	
	// Add hardcoded directories for components with proper lifecycle managers
	// These will be removed once all components implement the lifecycle interface
	allDirectories = append(allDirectories, []DirectoryConfig{
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